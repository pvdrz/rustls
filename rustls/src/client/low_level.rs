//! FIXME: docs

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use pki_types::UnixTime;
use std::sync::Arc;

use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::conn::ConnectionRandoms;
use crate::crypto::ActiveKeyExchange;
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::low_level::{
    ConnectionState, EmitState, ExpectState, GeneratedMessage, LlConnectionCommon,
};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{Compression, ECPointFormat};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtension, ClientHelloPayload, HandshakeMessagePayload,
    HandshakePayload, Random, ServerECDHParams, ServerKeyExchangePayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::tls12::ConnectionSecrets;
use crate::{
    AlertDescription, ClientConfig, ContentType, Error, HandshakeType, InvalidMessage,
    PeerMisbehaved, ProtocolVersion, ServerName, Side, SupportedCipherSuite, Tls12CipherSuite,
};

/// FIXME: docs
pub struct LlClientConnection {
    conn: LlConnectionCommon,
}

impl Deref for LlClientConnection {
    type Target = LlConnectionCommon;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl DerefMut for LlClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl LlClientConnection {
    /// FIXME: docs
    pub fn new(config: Arc<ClientConfig>, name: ServerName) -> Result<Self, Error> {
        Ok(Self {
            conn: LlConnectionCommon::new(ConnectionState::emit(EmitClientHello { config, name }))?,
        })
    }
}

struct EmitClientHello {
    config: Arc<ClientConfig>,
    name: ServerName,
}

impl EmitState for EmitClientHello {
    fn generate_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon,
    ) -> Result<GeneratedMessage, Error> {
        let random = Random::new(self.config.provider)?;

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
                random,
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

        let next_state = ConnectionState::expect(ExpectServerHello {
            config: self.config,
            name: self.name,
            transcript_buffer,
            random,
        });

        Ok(GeneratedMessage::new(msg, next_state))
    }
}

struct ExpectServerHello {
    config: Arc<ClientConfig>,
    name: ServerName,
    transcript_buffer: HandshakeHashBuffer,
    random: Random,
}

impl ExpectState for ExpectServerHello {
    fn process_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<ConnectionState, Error> {
        let payload = require_handshake_msg!(
            msg,
            HandshakeType::ServerHello,
            HandshakePayload::ServerHello
        )?;

        let Some(suite) = self
            .config
            .find_cipher_suite(payload.cipher_suite)
        else {
            return Ok(ConnectionState::emit_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::SelectedUnofferedCipherSuite,
            ));
        };
        let mut transcript = self
            .transcript_buffer
            .start_hash(suite.hash_provider());

        transcript.add_message(&msg);

        let suite = match suite {
            SupportedCipherSuite::Tls12(suite) => suite,
            SupportedCipherSuite::Tls13(_) => todo!(),
        };

        Ok(ConnectionState::expect(ExpectCertificate {
            config: self.config,
            name: self.name,
            suite,
            randoms: ConnectionRandoms::new(self.random, payload.random),
            transcript,
        }))
    }
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    name: ServerName,
    suite: &'static Tls12CipherSuite,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}

impl ExpectState for ExpectCertificate {
    fn process_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<ConnectionState, Error> {
        let payload = require_handshake_msg_move!(
            msg,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        if let Err(error) = self.config.verifier.verify_server_cert(
            &payload[0],
            &[],
            &self.name,
            &[],
            UnixTime::now(),
        ) {
            Ok(ConnectionState::emit_alert(
                match &error {
                    Error::InvalidCertificate(e) => e.clone().into(),
                    Error::PeerMisbehaved(_) => AlertDescription::IllegalParameter,
                    _ => AlertDescription::HandshakeFailure,
                },
                error,
            ))
        } else {
            Ok(ConnectionState::expect(ExpectServerKeyExchange {
                config: self.config,
                suite: self.suite,
                randoms: self.randoms,
                transcript: self.transcript,
            }))
        }
    }

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}

struct ExpectServerKeyExchange {
    config: Arc<ClientConfig>,
    suite: &'static Tls12CipherSuite,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}
impl ExpectState for ExpectServerKeyExchange {
    fn process_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<ConnectionState, Error> {
        let opaque_kx = require_handshake_msg_move!(
            msg,
            HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerKeyExchange
        )?;

        Ok(ConnectionState::expect(ExpectServerHelloDone {
            config: self.config,
            suite: self.suite,
            randoms: self.randoms,
            opaque_kx,
            transcript: self.transcript,
        }))
    }

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}

struct ExpectServerHelloDone {
    config: Arc<ClientConfig>,
    suite: &'static Tls12CipherSuite,
    opaque_kx: ServerKeyExchangePayload,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}

impl ExpectState for ExpectServerHelloDone {
    fn process_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<ConnectionState, Error> {
        match msg.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::CertificateRequest,
                        payload: HandshakePayload::CertificateRequest(_),
                    },
                ..
            } => Ok(ConnectionState::Expect(self)),
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::ServerHelloDone,
                        payload: HandshakePayload::ServerHelloDone,
                    },
                ..
            } => {
                let Some(ecdhe) = self
                    .opaque_kx
                    .unwrap_given_kxa(self.suite.kx)
                else {
                    return Ok(ConnectionState::emit_alert(
                        AlertDescription::DecodeError,
                        InvalidMessage::MissingKeyExchange,
                    ));
                };

                let mut kx_params = Vec::new();
                ecdhe.params.encode(&mut kx_params);

                let mut rd = Reader::init(&kx_params);
                let ecdh_params = ServerECDHParams::read(&mut rd)?;

                if rd.any_left() {
                    return Ok(ConnectionState::emit_alert(
                        AlertDescription::DecodeError,
                        InvalidMessage::InvalidDhParams,
                    ));
                }

                let Some(skxg) = self
                    .config
                    .find_kx_group(ecdh_params.curve_params.named_group)
                else {
                    return Ok(ConnectionState::emit_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup,
                    ));
                };

                let kx = skxg
                    .start()
                    .map_err(|_| Error::FailedToGetRandomBytes)?;

                Ok(ConnectionState::emit(EmitClientKeyExchange {
                    suite: self.suite,
                    kx,
                    ecdh_params,
                    randoms: self.randoms,
                    transcript: self.transcript,
                }))
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

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}

struct EmitClientKeyExchange {
    suite: &'static Tls12CipherSuite,
    kx: Box<dyn ActiveKeyExchange>,
    ecdh_params: ServerECDHParams,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}
impl EmitState for EmitClientKeyExchange {
    fn generate_message(
        mut self: Box<Self>,
        _conn: &mut LlConnectionCommon,
    ) -> Result<GeneratedMessage, Error> {
        let mut buf = Vec::new();
        let ecpoint = PayloadU8::new(Vec::from(self.kx.pub_key()));
        ecpoint.encode(&mut buf);
        let pubkey = Payload::new(buf);

        let msg = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientKeyExchange,
                payload: HandshakePayload::ClientKeyExchange(pubkey),
            }),
        };

        self.transcript.add_message(&msg);

        let next_state = ConnectionState::emit(EmitChangeCipherSpec {
            kx: self.kx,
            peer_pub_key: self.ecdh_params.public.0,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
        });

        Ok(GeneratedMessage::new(msg, next_state))
    }
}

struct EmitChangeCipherSpec {
    kx: Box<dyn ActiveKeyExchange>,
    peer_pub_key: Vec<u8>,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    transcript: HandshakeHash,
}

impl EmitState for EmitChangeCipherSpec {
    fn generate_message(
        self: Box<Self>,
        conn: &mut LlConnectionCommon,
    ) -> Result<GeneratedMessage, Error> {
        let secrets = ConnectionSecrets::from_key_exchange(
            self.kx,
            &self.peer_pub_key,
            Some(self.transcript.get_current_hash()),
            self.randoms,
            self.suite,
        )?;

        let (dec, enc) = secrets.make_cipher_pair(Side::Client);

        conn.record_layer
            .prepare_message_encrypter(enc);
        conn.record_layer
            .prepare_message_decrypter(dec);
        conn.record_layer.start_encrypting();

        let msg = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        };

        let next_state = ConnectionState::emit(EmitFinished {
            secrets,
            transcript: self.transcript,
        });

        Ok(GeneratedMessage::new(msg, next_state))
    }
}

struct EmitFinished {
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
}
impl EmitState for EmitFinished {
    fn generate_message(
        mut self: Box<Self>,
        _conn: &mut LlConnectionCommon,
    ) -> Result<GeneratedMessage, Error> {
        let vh = self.transcript.get_current_hash();
        let verify_data = self.secrets.client_verify_data(&vh);
        let verify_data_payload = Payload::new(verify_data);

        let msg = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(verify_data_payload),
            }),
        };

        self.transcript.add_message(&msg);

        Ok(GeneratedMessage::new(
            msg,
            ConnectionState::expect(ExpectChangeCipherSpec {
                transcript: self.transcript,
            }),
        )
        .require_encryption(true))
    }
}

struct ExpectChangeCipherSpec {
    transcript: HandshakeHash,
}

impl ExpectState for ExpectChangeCipherSpec {
    fn process_message(
        self: Box<Self>,
        conn: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<ConnectionState, Error> {
        match msg.payload {
            MessagePayload::ChangeCipherSpec(_) => {
                conn.record_layer.start_decrypting();

                Ok(ConnectionState::expect(ExpectFinished {
                    transcript: self.transcript,
                }))
            }
            payload => Err(inappropriate_message(
                &payload,
                &[ContentType::ChangeCipherSpec],
            )),
        }
    }
}

struct ExpectFinished {
    transcript: HandshakeHash,
}

impl ExpectState for ExpectFinished {
    fn process_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<ConnectionState, Error> {
        let _ = require_handshake_msg!(msg, HandshakeType::Finished, HandshakePayload::Finished)?;

        Ok(ConnectionState::HandshakeDone)
    }

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}
