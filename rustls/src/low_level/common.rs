//! FIXME: docs

use core::num::NonZeroUsize;

use alloc::vec;
use alloc::vec::Vec;
use pki_types::UnixTime;
use std::sync::Arc;

use crate::client::tls12::ServerKxDetails;
use crate::conn::ConnectionRandoms;
use crate::crypto::cipher::OpaqueMessage;
use crate::internal::record_layer::RecordLayer;
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::ECPointFormat;
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtension, ServerECDHParams, ServerKeyExchangePayload,
};
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
use crate::{InvalidMessage, ServerName, Side, SupportedCipherSuite, Tls12CipherSuite};

#[derive(Debug)]
enum CommonState {
    Unreachable,
    StartHandshake,
    SendClientHello,
    WaitServerHello,
    WaitCert {
        offset: usize,
        suite: &'static Tls12CipherSuite,
        randoms: ConnectionRandoms,
    },
    WaitServerKeyExchange {
        offset: usize,
        suite: &'static Tls12CipherSuite,
        randoms: ConnectionRandoms,
    },
    WaitServerHelloDone {
        offset: usize,
        suite: &'static Tls12CipherSuite,
        opaque_kx: ServerKeyExchangePayload,
        randoms: ConnectionRandoms,
    },
    WriteClientKeyExchange {
        suite: &'static Tls12CipherSuite,
        server_kx: ServerKxDetails,
        randoms: ConnectionRandoms,
    },
    SendClientKeyExchange,
    WriteChangeCipherSpec,
    SendChangeCipherSpec,
    WriteFinished,
    SendFinished,
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
}

impl LlConnectionCommon {
    /// FIXME: docs
    pub fn new(config: Arc<ClientConfig>, name: ServerName) -> Self {
        Self {
            config,
            name,
            state: CommonState::StartHandshake,
            record_layer: RecordLayer::new(),
        }
    }

    /// Processes TLS records in the `incoming_tls` buffer
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> Result<Status<'c, 'i>, Error> {
        loop {
            std::dbg!(&self.state);
            match self.state.take() {
                CommonState::Unreachable => unreachable!(),
                state @ (CommonState::StartHandshake
                | CommonState::WriteClientKeyExchange { .. }
                | CommonState::WriteChangeCipherSpec
                | CommonState::WriteFinished) => {
                    self.state = state;

                    return Ok(Status {
                        discard: 0,
                        state: State::MustEncryptTlsData(MustEncryptTlsData { conn: self }),
                    });
                }
                state @ (CommonState::SendClientHello
                | CommonState::SendClientKeyExchange
                | CommonState::SendChangeCipherSpec
                | CommonState::SendFinished) => {
                    self.state = state;

                    return Ok(Status {
                        discard: 0,
                        state: State::MustTransmitTlsData(MustTransmitTlsData { conn: self }),
                    });
                }
                state @ CommonState::WaitServerHello => {
                    if incoming_tls.iter().all(|&b| b == 0) {
                        self.state = state;

                        return Ok(Status {
                            discard: 0,
                            state: State::NeedsMoreTlsData { num_bytes: None },
                        });
                    } else {
                        let mut reader = Reader::init(incoming_tls);
                        let m = OpaqueMessage::read(&mut reader)
                            .unwrap()
                            .into_plain_message();
                        let read_bytes = reader.used();

                        let msg = Message::try_from(m).unwrap();

                        match msg.payload {
                            MessagePayload::Handshake {
                                parsed:
                                    HandshakeMessagePayload {
                                        typ: HandshakeType::ServerHello,
                                        payload: HandshakePayload::ServerHello(payload),
                                    },
                                ..
                            } => {
                                std::println!("Received ServerHello: {:?}", payload);

                                let suite = self
                                    .config
                                    .find_cipher_suite(payload.cipher_suite)
                                    .unwrap();

                                let suite = match suite {
                                    SupportedCipherSuite::Tls12(suite) => suite,
                                    SupportedCipherSuite::Tls13(_) => todo!(),
                                };

                                self.state = CommonState::WaitCert {
                                    offset: read_bytes,
                                    suite,
                                    randoms: ConnectionRandoms::new(
                                        Random([0u8; 32]),
                                        payload.random,
                                    ),
                                };
                            }
                            _ => {
                                return Err(Error::InvalidMessage(
                                    InvalidMessage::UnexpectedMessage("expected server hello"),
                                ));
                            }
                        }
                    }
                }
                CommonState::WaitCert {
                    offset,
                    suite,
                    randoms,
                } => {
                    if incoming_tls[offset..]
                        .iter()
                        .all(|&b| b == 0)
                    {
                        self.state = CommonState::WaitCert {
                            offset: 0,
                            suite,
                            randoms,
                        };

                        return Ok(Status {
                            discard: offset,
                            state: State::NeedsMoreTlsData { num_bytes: None },
                        });
                    } else {
                        let mut reader = Reader::init(&incoming_tls[offset..]);
                        let m = OpaqueMessage::read(&mut reader)
                            .unwrap()
                            .into_plain_message();

                        let msg = Message::try_from(m).unwrap();

                        match msg.payload {
                            MessagePayload::Handshake {
                                parsed:
                                    HandshakeMessagePayload {
                                        typ: HandshakeType::Certificate,
                                        payload: HandshakePayload::Certificate(payload),
                                    },
                                ..
                            } => {
                                self.config
                                    .verifier
                                    .verify_server_cert(
                                        &payload[0],
                                        &[],
                                        &self.name,
                                        &[],
                                        UnixTime::now(),
                                    )
                                    .unwrap();

                                self.state = CommonState::WaitServerKeyExchange {
                                    offset: offset + reader.used(),
                                    suite,
                                    randoms,
                                };
                            }
                            _ => {
                                return Err(Error::InvalidMessage(
                                    InvalidMessage::UnexpectedMessage(
                                        "expected certificate request",
                                    ),
                                ));
                            }
                        }
                    }
                }
                CommonState::WaitServerKeyExchange {
                    offset,
                    suite,
                    randoms,
                } => {
                    let mut reader = Reader::init(&incoming_tls[offset..]);
                    let m = OpaqueMessage::read(&mut reader)
                        .unwrap()
                        .into_plain_message();

                    let msg = Message::try_from(m).unwrap();

                    match msg.payload {
                        MessagePayload::Handshake {
                            parsed:
                                HandshakeMessagePayload {
                                    typ: HandshakeType::ServerKeyExchange,
                                    payload: HandshakePayload::ServerKeyExchange(opaque_kx),
                                },
                            ..
                        } => {
                            self.state = CommonState::WaitServerHelloDone {
                                offset: offset + reader.used(),
                                suite,
                                randoms,
                                opaque_kx,
                            };
                        }
                        _ => {
                            return Err(Error::InvalidMessage(InvalidMessage::UnexpectedMessage(
                                "expected server key exchange",
                            )));
                        }
                    }
                }
                CommonState::WaitServerHelloDone {
                    offset,
                    suite,
                    randoms,
                    opaque_kx,
                } => {
                    let mut reader = Reader::init(&incoming_tls[offset..]);
                    let m = OpaqueMessage::read(&mut reader)
                        .unwrap()
                        .into_plain_message();

                    let msg = Message::try_from(m).unwrap();

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
                                offset: offset + reader.used(),
                                suite,
                                randoms,
                                opaque_kx,
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
                            };
                        }
                        _ => {
                            std::dbg!(msg.payload);
                            return Err(Error::InvalidMessage(InvalidMessage::UnexpectedMessage(
                                "expected server hello done",
                            )));
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

                self.state = CommonState::SendClientHello;

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

                Message {
                    version: ProtocolVersion::TLSv1_0,
                    payload: MessagePayload::handshake(payload),
                }
            }

            CommonState::WriteClientKeyExchange {
                suite,
                server_kx,
                randoms,
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

                let payload = HandshakeMessagePayload {
                    typ: HandshakeType::ClientKeyExchange,
                    payload: HandshakePayload::ClientKeyExchange(pubkey),
                };

                let secrets = ConnectionSecrets::from_key_exchange(
                    kx,
                    &ecdh_params.public.0,
                    None,
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

                self.state = CommonState::SendClientKeyExchange;

                Message {
                    version: ProtocolVersion::TLSv1_2,
                    payload: MessagePayload::handshake(payload),
                }
            }
            CommonState::WriteChangeCipherSpec => {
                self.state = CommonState::SendChangeCipherSpec;

                Message {
                    version: ProtocolVersion::TLSv1_2,
                    payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
                }
            }
            CommonState::WriteFinished => {
                let verify_data_payload = Payload::new(vec![]);

                self.state = CommonState::SendFinished;
                is_encrypted = true;

                Message {
                    version: ProtocolVersion::TLSv1_2,
                    payload: MessagePayload::handshake(HandshakeMessagePayload {
                        typ: HandshakeType::Finished,
                        payload: HandshakePayload::Finished(verify_data_payload),
                    }),
                }
            }
            _ => unreachable!(),
        };

        let mut written_bytes = 0;

        for m in message_fragmenter.fragment_message(&std::dbg!(msg).into()) {
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
        match self.state {
            CommonState::SendClientHello => {
                self.state = CommonState::WaitServerHello;
            }
            CommonState::SendClientKeyExchange => {
                self.state = CommonState::WriteChangeCipherSpec;
            }
            CommonState::SendChangeCipherSpec => {
                self.state = CommonState::WriteFinished;
            }
            CommonState::SendFinished => {
                todo!()
            }
            _ => unreachable!(),
        }
    }

    fn encrypt_traffic_transit(
        &self,
        _application_data: &[u8],
        _outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        todo!()
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
pub struct AppDataRecord<'i> {
    /// number of the bytes associated to this record that must discarded from the front of
    /// the `incoming_tls` buffer before the next `process_tls_record` call
    pub discard: NonZeroUsize,

    /// FIXME: docs
    pub payload: &'i [u8],
}

/// FIXME: docs
pub struct AppDataAvailable<'c, 'i> {
    /// FIXME: docs
    _conn: &'c mut LlConnectionCommon,
    /// FIXME: docs
    _incoming_tls: Option<&'i mut [u8]>,
}

impl<'c: 'i, 'i> Iterator for AppDataAvailable<'c, 'i> {
    type Item = Result<AppDataRecord<'i>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
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
