//! FIXME: docs

use core::num::NonZeroUsize;

use alloc::vec;
use alloc::vec::Vec;
use pki_types::UnixTime;
use std::sync::Arc;

use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::client::tls12::ServerKxDetails;
use crate::conn::ConnectionRandoms;
use crate::crypto::cipher::{OpaqueMessage, PlainMessage};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::internal::record_layer::RecordLayer;
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::ECPointFormat;
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtension, ServerECDHParams, ServerKeyExchangePayload,
};
use crate::msgs::message::MessageError;
use crate::tls12::ConnectionSecrets;
use crate::{
    msgs::{
        enums::Compression,
        fragmenter::MessageFragmenter,
        handshake::{
            ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random, SessionId,
        },
        message::{Message, MessagePayload},
    },
    ClientConfig, Error, HandshakeType, ProtocolVersion,
};
use crate::{
    ContentType, InvalidMessage, ServerName, Side, SupportedCipherSuite, Tls12CipherSuite,
};

enum CommonState {
    Unreachable,
    StartHandshake,
    SendClientHello {
        transcript_buffer: HandshakeHashBuffer,
    },
    WaitServerHello {
        transcript_buffer: HandshakeHashBuffer,
    },
    WaitCert {
        suite: &'static Tls12CipherSuite,
        randoms: ConnectionRandoms,
        transcript: HandshakeHash,
    },
    WaitServerKeyExchange {
        suite: &'static Tls12CipherSuite,
        randoms: ConnectionRandoms,
        transcript: HandshakeHash,
    },
    WaitServerHelloDone {
        suite: &'static Tls12CipherSuite,
        opaque_kx: ServerKeyExchangePayload,
        randoms: ConnectionRandoms,
        transcript: HandshakeHash,
    },
    WriteClientKeyExchange {
        suite: &'static Tls12CipherSuite,
        server_kx: ServerKxDetails,
        randoms: ConnectionRandoms,
        transcript: HandshakeHash,
    },
    SendClientKeyExchange {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    WriteChangeCipherSpec {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    SendChangeCipherSpec {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    WriteFinished {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    SendFinished,
    WaitChangeCipherSpec,
    WaitFinished,
    HandshakeDone,
}

impl CommonState {
    fn take(&mut self) -> Self {
        core::mem::replace(self, Self::Unreachable)
    }
}

/// both `LlClientConnection` and `LlServerConnection` implement `DerefMut<Target = LlConnectionCommon>`
pub struct LlConnectionCommon {
    config: Arc<ClientConfig>,
    name: ServerName,
    state: CommonState,
    record_layer: RecordLayer,
    offset: usize,
}

impl LlConnectionCommon {
    /// FIXME: docs
    pub fn new(config: Arc<ClientConfig>, name: ServerName) -> Self {
        Self {
            config,
            name,
            state: CommonState::StartHandshake,
            record_layer: RecordLayer::new(),
            offset: 0,
        }
    }

    /// Processes TLS records in the `incoming_tls` buffer
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> Result<Status<'c, 'i>, Error> {
        loop {
            match self.state.take() {
                CommonState::Unreachable => unreachable!(),
                state @ (CommonState::StartHandshake
                | CommonState::WriteClientKeyExchange { .. }
                | CommonState::WriteChangeCipherSpec { .. }
                | CommonState::WriteFinished { .. }) => {
                    self.state = state;
                    return Ok(Status {
                        discard: 0,
                        state: State::MustEncryptTlsData(MustEncryptTlsData { conn: self }),
                    });
                }
                state @ (CommonState::SendClientHello { .. }
                | CommonState::SendClientKeyExchange { .. }
                | CommonState::SendChangeCipherSpec { .. }
                | CommonState::SendFinished) => {
                    self.state = state;

                    return Ok(Status {
                        discard: 0,
                        state: State::MustTransmitTlsData(MustTransmitTlsData { conn: self }),
                    });
                }
                state @ (CommonState::WaitServerHello { .. }
                | CommonState::WaitCert { .. }
                | CommonState::WaitServerKeyExchange { .. }
                | CommonState::WaitServerHelloDone { .. }
                | CommonState::WaitChangeCipherSpec
                | CommonState::WaitFinished)
                    if incoming_tls[self.offset..]
                        .iter()
                        .all(|&b| b == 0) =>
                {
                    self.state = state;
                    return Ok(Status {
                        discard: 0,
                        state: State::NeedsMoreTlsData { num_bytes: None },
                    });
                }
                CommonState::WaitServerHello { transcript_buffer } => {
                    let msg = self.read_message(incoming_tls, None)?;

                    let payload = require_handshake_msg!(
                        msg,
                        HandshakeType::ServerHello,
                        HandshakePayload::ServerHello
                    )?;

                    let suite = self
                        .config
                        .find_cipher_suite(payload.cipher_suite)
                        .unwrap();

                    let mut transcript = transcript_buffer.start_hash(suite.hash_provider());

                    transcript.add_message(&msg);

                    let suite = match suite {
                        SupportedCipherSuite::Tls12(suite) => suite,
                        SupportedCipherSuite::Tls13(_) => todo!(),
                    };

                    self.state = CommonState::WaitCert {
                        suite,
                        randoms: ConnectionRandoms::new(Random([0u8; 32]), payload.random),
                        transcript,
                    };
                }
                CommonState::WaitCert {
                    suite,
                    randoms,
                    mut transcript,
                } => {
                    let msg = self.read_message(incoming_tls, Some(&mut transcript))?;

                    let payload = require_handshake_msg_move!(
                        msg,
                        HandshakeType::Certificate,
                        HandshakePayload::Certificate
                    )?;

                    self.config
                        .verifier
                        .verify_server_cert(&payload[0], &[], &self.name, &[], UnixTime::now())
                        .unwrap();

                    self.state = CommonState::WaitServerKeyExchange {
                        suite,
                        randoms,
                        transcript,
                    };
                }
                CommonState::WaitServerKeyExchange {
                    suite,
                    randoms,
                    mut transcript,
                } => {
                    let msg = self.read_message(incoming_tls, Some(&mut transcript))?;

                    let opaque_kx = require_handshake_msg_move!(
                        msg,
                        HandshakeType::ServerKeyExchange,
                        HandshakePayload::ServerKeyExchange
                    )?;

                    self.state = CommonState::WaitServerHelloDone {
                        suite,
                        randoms,
                        opaque_kx,
                        transcript,
                    };
                }
                CommonState::WaitServerHelloDone {
                    suite,
                    randoms,
                    opaque_kx,
                    mut transcript,
                } => {
                    let msg = self.read_message(incoming_tls, Some(&mut transcript))?;
                    match msg.payload {
                        MessagePayload::Handshake {
                            parsed:
                                HandshakeMessagePayload {
                                    typ: HandshakeType::CertificateRequest,
                                    payload: HandshakePayload::CertificateRequest(_),
                                },
                            ..
                        } => {
                            self.state = CommonState::WaitServerHelloDone {
                                suite,
                                randoms,
                                opaque_kx,
                                transcript,
                            };
                        }
                        MessagePayload::Handshake {
                            parsed:
                                HandshakeMessagePayload {
                                    typ: HandshakeType::ServerHelloDone,
                                    payload: HandshakePayload::ServerHelloDone,
                                },
                            ..
                        } => {
                            let ecdhe = opaque_kx
                                .unwrap_given_kxa(suite.kx)
                                .unwrap();

                            let mut kx_params = Vec::new();
                            ecdhe.params.encode(&mut kx_params);
                            let server_kx = ServerKxDetails::new(kx_params, ecdhe.dss);

                            self.state = CommonState::WriteClientKeyExchange {
                                suite,
                                server_kx,
                                randoms,
                                transcript,
                            };
                        }
                        payload => {
                            return Err(inappropriate_handshake_message(
                                &payload,
                                &[ContentType::Handshake],
                                &[
                                    HandshakeType::ServerHelloDone,
                                    HandshakeType::CertificateRequest,
                                ],
                            ));
                        }
                    }
                }
                CommonState::WaitChangeCipherSpec => {
                    let msg = self.read_message(incoming_tls, None)?;
                    match msg.payload {
                        MessagePayload::ChangeCipherSpec(_) => {
                            self.record_layer.start_decrypting();
                            self.state = CommonState::WaitFinished;
                        }
                        payload => {
                            return Err(inappropriate_message(
                                &payload,
                                &[ContentType::ChangeCipherSpec],
                            ));
                        }
                    }
                }
                CommonState::WaitFinished => {
                    let msg = self.read_message(incoming_tls, None)?;

                    let _ = require_handshake_msg!(
                        msg,
                        HandshakeType::Finished,
                        HandshakePayload::Finished
                    )?;

                    self.state = CommonState::HandshakeDone;
                }
                state @ CommonState::HandshakeDone => {
                    self.state = state;

                    let mut reader = Reader::init(&incoming_tls[self.offset..]);
                    match OpaqueMessage::read(&mut reader) {
                        Ok(msg) => match msg.typ {
                            ContentType::ApplicationData => {
                                return Ok(Status {
                                    discard: 0,
                                    state: State::AppDataAvailable(AppDataAvailable {
                                        incoming_tls: Some(incoming_tls),
                                        conn: self,
                                    }),
                                });
                            }
                            content_type => {
                                panic!("{:?}", content_type);
                            }
                        },
                        Err(_) => {
                            return Ok(Status {
                                discard: 0,
                                state: State::TrafficTransit(TrafficTransit { conn: self }),
                            });
                        }
                    }
                }
            }
        }
    }

    fn encrypt_app_data(
        &self,
        _application_data: &[u8],
        _outgoing_tls: &mut [u8],
    ) -> Result<usize, InsufficientSizeError> {
        todo!()
    }

    fn app_data_done(&self) {
        todo!()
    }

    fn encrypt_tls_data(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        let message_fragmenter = MessageFragmenter::default();
        let mut is_encrypted = false;

        let msg = match self.state.take() {
            CommonState::StartHandshake => {
                let support_tls12 = self
                    .config
                    .supports_version(ProtocolVersion::TLSv1_2);

                let mut supported_versions = Vec::new();
                if support_tls12 {
                    supported_versions.push(ProtocolVersion::TLSv1_2);
                }

                let payload = HandshakeMessagePayload {
                    typ: HandshakeType::ClientHello,
                    payload: HandshakePayload::ClientHello(ClientHelloPayload {
                        client_version: ProtocolVersion::TLSv1_2,
                        random: Random([0u8; 32]),
                        session_id: SessionId::empty(),
                        cipher_suites: self
                            .config
                            .cipher_suites
                            .iter()
                            .map(|cs| cs.suite())
                            .collect(),
                        compression_methods: vec![Compression::Null],
                        extensions: vec![
                            ClientExtension::SupportedVersions(supported_versions),
                            ClientExtension::ECPointFormats(ECPointFormat::SUPPORTED.to_vec()),
                            ClientExtension::NamedGroups(
                                self.config
                                    .kx_groups
                                    .iter()
                                    .map(|skxg| skxg.name())
                                    .collect(),
                            ),
                            ClientExtension::SignatureAlgorithms(
                                self.config
                                    .verifier
                                    .supported_verify_schemes(),
                            ),
                            ClientExtension::ExtendedMasterSecretRequest,
                            ClientExtension::CertificateStatusRequest(
                                CertificateStatusRequest::build_ocsp(),
                            ),
                        ],
                    }),
                };

                let msg = Message {
                    version: ProtocolVersion::TLSv1_0,
                    payload: MessagePayload::handshake(payload),
                };

                let mut transcript_buffer = HandshakeHashBuffer::new();
                transcript_buffer.add_message(&msg);
                self.state = CommonState::SendClientHello { transcript_buffer };

                msg
            }

            CommonState::WriteClientKeyExchange {
                suite,
                server_kx,
                randoms,
                mut transcript,
            } => {
                let mut rd = Reader::init(&server_kx.kx_params);
                let ecdh_params = ServerECDHParams::read(&mut rd).unwrap();
                assert!(!rd.any_left());

                let named_group = ecdh_params.curve_params.named_group;
                let skxg = self
                    .config
                    .find_kx_group(named_group)
                    .unwrap();

                let kx = skxg.start().unwrap();

                let mut buf = Vec::new();
                let ecpoint = PayloadU8::new(Vec::from(kx.pub_key()));
                ecpoint.encode(&mut buf);
                let pubkey = Payload::new(buf);

                let msg = Message {
                    version: ProtocolVersion::TLSv1_2,
                    payload: MessagePayload::handshake(HandshakeMessagePayload {
                        typ: HandshakeType::ClientKeyExchange,
                        payload: HandshakePayload::ClientKeyExchange(pubkey),
                    }),
                };

                transcript.add_message(&msg);

                let secrets = ConnectionSecrets::from_key_exchange(
                    kx,
                    &ecdh_params.public.0,
                    Some(transcript.get_current_hash()),
                    randoms,
                    suite,
                )
                .unwrap();

                let (dec, enc) = secrets.make_cipher_pair(Side::Client);

                self.record_layer
                    .prepare_message_encrypter(enc);
                self.record_layer
                    .prepare_message_decrypter(dec);
                self.record_layer.start_encrypting();

                self.state = CommonState::SendClientKeyExchange {
                    secrets,
                    transcript,
                };

                msg
            }
            CommonState::WriteChangeCipherSpec {
                secrets,
                mut transcript,
            } => {
                let msg = Message {
                    version: ProtocolVersion::TLSv1_2,
                    payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
                };

                transcript.add_message(&msg);
                self.state = CommonState::SendChangeCipherSpec {
                    secrets,
                    transcript,
                };

                msg
            }
            CommonState::WriteFinished {
                mut transcript,
                secrets,
            } => {
                let vh = transcript.get_current_hash();
                let verify_data = secrets.client_verify_data(&vh);
                let verify_data_payload = Payload::new(verify_data);

                is_encrypted = true;

                let msg = Message {
                    version: ProtocolVersion::TLSv1_2,
                    payload: MessagePayload::handshake(HandshakeMessagePayload {
                        typ: HandshakeType::Finished,
                        payload: HandshakePayload::Finished(verify_data_payload),
                    }),
                };

                transcript.add_message(&msg);
                self.state = CommonState::SendFinished;

                msg
            }
            _ => unreachable!(),
        };

        let mut written_bytes = 0;

        for m in message_fragmenter.fragment_message(&msg.into()) {
            let opaque_msg = if is_encrypted {
                self.record_layer.encrypt_outgoing(m)
            } else {
                m.to_unencrypted_opaque()
            };

            let bytes = opaque_msg.encode();

            if bytes.len() > outgoing_tls.len() {
                return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                    required_size: bytes.len(),
                }));
            }

            outgoing_tls[written_bytes..written_bytes + bytes.len()].copy_from_slice(&bytes);
            written_bytes += bytes.len();
        }

        Ok(written_bytes)
    }

    fn tls_data_done(&mut self) {
        match self.state.take() {
            CommonState::SendClientHello { transcript_buffer } => {
                self.state = CommonState::WaitServerHello { transcript_buffer };
            }
            CommonState::SendClientKeyExchange {
                secrets,
                transcript,
            } => {
                self.state = CommonState::WriteChangeCipherSpec {
                    secrets,
                    transcript,
                };
            }
            CommonState::SendChangeCipherSpec {
                secrets,
                transcript,
            } => {
                self.state = CommonState::WriteFinished {
                    secrets,
                    transcript,
                };
            }
            CommonState::SendFinished => {
                self.state = CommonState::WaitChangeCipherSpec;
            }
            _ => unreachable!(),
        }
    }

    fn encrypt_traffic_transit(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        let msg: PlainMessage = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ApplicationData(Payload(application_data.to_vec())),
        }
        .into();

        let opaque_msg = self
            .record_layer
            .encrypt_outgoing(msg.borrow());

        let bytes = opaque_msg.encode();
        outgoing_tls[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    fn read_message(
        &mut self,
        incoming_tls: &[u8],
        transcript_opt: Option<&mut HandshakeHash>,
    ) -> Result<Message, Error> {
        let mut reader = Reader::init(&incoming_tls[self.offset..]);
        let m = OpaqueMessage::read(&mut reader).map_err(|err| match err {
            MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                InvalidMessage::MessageTooShort
            }
            MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
            MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
            MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
            MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
        })?;
        self.offset += reader.used();

        let decrypted = self
            .record_layer
            .decrypt_incoming(m)?
            .expect("we don't support early data yet");

        let msg = decrypted.plaintext.try_into()?;
        if let Some(transcript) = transcript_opt {
            transcript.add_message(&msg);
        }

        std::println!("Read {:?}", msg);

        Ok(msg)
    }
}

/// FIXME: docs
#[must_use]
pub struct Status<'c, 'i> {
    /// number of bytes that must be discarded from the *front* of `incoming_tls` *after* handling
    /// `state` and *before* the next `process_tls_records` call
    pub discard: usize,

    /// the current state of the handshake process
    pub state: State<'c, 'i>,
}

/// FIXME: docs
pub enum State<'c, 'i> {
    /// One, or more, application data record is available
    AppDataAvailable(AppDataAvailable<'c, 'i>),

    /// Application data may be encrypted at this stage of the handshake
    MayEncryptAppData(MayEncryptAppData<'c>),

    /// A Handshake record must be encrypted into the `outgoing_tls` buffer
    MustEncryptTlsData(MustEncryptTlsData<'c>),

    /// TLS records related to the handshake have been placed in the `outgoing_tls` buffer and must
    /// be transmitted to continue with the handshake process
    MustTransmitTlsData(MustTransmitTlsData<'c>),

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the handshake
    NeedsMoreTlsData {
        /// number of bytes required to complete a TLS record. `None` indicates that
        /// no information is available
        num_bytes: Option<NonZeroUsize>,
    },

    /// Handshake is complete.
    TrafficTransit(TrafficTransit<'c>),
    // .. other variants are omitted for now ..
}

/// A decrypted application data record
#[derive(Debug)]
pub struct AppDataRecord {
    /// number of the bytes associated to this record that must discarded from the front of
    /// the `incoming_tls` buffer before the next `process_tls_record` call
    pub discard: NonZeroUsize,

    /// FIXME: docs
    pub payload: Vec<u8>,
}

/// FIXME: docs
pub struct AppDataAvailable<'c, 'i> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
    /// FIXME: docs
    incoming_tls: Option<&'i mut [u8]>,
}

impl<'c: 'i, 'i> Iterator for AppDataAvailable<'c, 'i> {
    type Item = Result<AppDataRecord, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.conn.offset;

        match self
            .conn
            .read_message(self.incoming_tls.as_deref()?, None)
        {
            Ok(msg) => match msg.payload {
                MessagePayload::ApplicationData(payload) => Some(Ok(AppDataRecord {
                    discard: self.conn.offset.try_into().unwrap(),
                    payload: payload.0,
                })),
                _ => {
                    self.conn.offset = offset;
                    None
                }
            },
            Err(err) => Some(Err(err)),
        }
    }
}

impl<'c, 'i> AppDataAvailable<'c, 'i> {
    /// returns the payload size of the next app-data record *without* decrypting it
    ///
    /// returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        todo!()
    }
}

/// FIXME: docs
pub struct MayEncryptAppData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

/// Provided buffer was too small
#[derive(Debug)]
pub struct InsufficientSizeError {
    /// buffer must be at least this size
    pub required_size: usize,
}

impl<'c> MayEncryptAppData<'c> {
    /// encrypts `application_data` into `outgoing_tls`
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, InsufficientSizeError> {
        self.conn
            .encrypt_app_data(application_data, outgoing_tls)
    }

    /// No more encryption will be performed; continue with the handshake process
    pub fn done(self) {
        self.conn.app_data_done()
    }
}

/// FIXME: docs
pub struct MustEncryptTlsData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

/// An error occurred while encrypting a handshake record
#[derive(Debug)]
pub enum EncryptError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// The handshake record has already been encrypted; do not call `encrypt` again
    AlreadyEncrypted,
}

impl<'c> MustEncryptTlsData<'c> {
    /// Encrypts a handshake record into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        self.conn.encrypt_tls_data(outgoing_tls)
    }
}

/// FIXME: docs
pub struct MustTransmitTlsData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

impl<'c> MustTransmitTlsData<'c> {
    /// FIXME: docs
    pub fn done(self) {
        self.conn.tls_data_done()
    }
}

/// FIXME: docs
pub struct TrafficTransit<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

impl<'c> TrafficTransit<'c> {
    /// Encrypts `application_data` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        self.conn
            .encrypt_traffic_transit(application_data, outgoing_tls)
    }
}
