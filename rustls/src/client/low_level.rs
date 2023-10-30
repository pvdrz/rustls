//! FIXME: docs

use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use pki_types::UnixTime;
use std::sync::Arc;

use crate::check::inappropriate_handshake_message;
use crate::conn::ConnectionRandoms;
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::low_level::{
    log_msg, CommonState, ExpectState, GeneratedMessage, LlConnectionCommon, SendState, WriteState,
};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{Compression, ECPointFormat};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtension, ClientHelloPayload, HandshakeMessagePayload,
    HandshakePayload, Random, ServerECDHParams, ServerKeyExchangePayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::{
    AlertDescription, ClientConfig, ContentType, Error, HandshakeType, InvalidMessage,
    PeerMisbehaved, ProtocolVersion, ServerName, SupportedCipherSuite, Tls12CipherSuite,
};

use super::tls12::ServerKxDetails;

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
            conn: LlConnectionCommon::new(config, name)?,
        })
    }
}

pub(crate) struct WriteClientHello {
    random: Random,
}

impl WriteClientHello {
    pub(crate) fn new(config: &ClientConfig) -> Result<Self, Error> {
        Ok(Self {
            random: Random::new(config.provider)?,
        })
    }

    pub(crate) fn generate_message(self, common: &mut LlConnectionCommon) -> GeneratedMessage {
        let support_tls12 = common
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
                random: self.random,
                session_id: SessionId::empty(),
                cipher_suites: common
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
                        common
                            .config
                            .kx_groups
                            .iter()
                            .map(|skxg| skxg.name())
                            .collect(),
                    ),
                    ClientExtension::SignatureAlgorithms(
                        common
                            .config
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
        log_msg(&msg, false);

        let mut transcript_buffer = HandshakeHashBuffer::new();
        transcript_buffer.add_message(&msg);
        let next_state = CommonState::Send(SendState::ClientHello(SendClientHello {
            transcript_buffer,
            random: self.random,
        }));

        GeneratedMessage::new(msg, next_state)
    }
}

pub(crate) struct SendClientHello {
    transcript_buffer: HandshakeHashBuffer,
    random: Random,
}

impl SendClientHello {
    pub(crate) fn tls_data_done(self) -> CommonState {
        CommonState::Expect(ExpectState::ServerHello(ExpectServerHello {
            transcript_buffer: self.transcript_buffer,
            random: self.random,
        }))
    }
}

pub(crate) struct ExpectServerHello {
    transcript_buffer: HandshakeHashBuffer,
    random: Random,
}

impl ExpectServerHello {
    pub(crate) fn process_message(
        self,
        common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        let payload = require_handshake_msg!(
            msg,
            HandshakeType::ServerHello,
            HandshakePayload::ServerHello
        )?;
        if let Some(suite) = common
            .config
            .find_cipher_suite(payload.cipher_suite)
        {
            let mut transcript = self
                .transcript_buffer
                .start_hash(suite.hash_provider());

            transcript.add_message(&msg);

            let suite = match suite {
                SupportedCipherSuite::Tls12(suite) => suite,
                SupportedCipherSuite::Tls13(_) => todo!(),
            };

            Ok(CommonState::Expect(ExpectState::Certificate(
                ExpectCertificate {
                    suite,
                    randoms: ConnectionRandoms::new(self.random, payload.random),
                    transcript,
                },
            )))
        } else {
            Ok(CommonState::Write(WriteState::Alert {
                description: AlertDescription::HandshakeFailure,
                error: PeerMisbehaved::SelectedUnofferedCipherSuite.into(),
            }))
        }
    }

    pub(crate) fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        None
    }
}

pub(crate) struct ExpectCertificate {
    suite: &'static Tls12CipherSuite,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}

impl ExpectCertificate {
    pub(crate) fn process_message(
        self,
        common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        let payload = require_handshake_msg_move!(
            msg,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        if let Err(error) = common
            .config
            .verifier
            .verify_server_cert(&payload[0], &[], &common.name, &[], UnixTime::now())
        {
            Ok(CommonState::Write(WriteState::Alert {
                description: match &error {
                    Error::InvalidCertificate(e) => e.clone().into(),
                    Error::PeerMisbehaved(_) => AlertDescription::IllegalParameter,
                    _ => AlertDescription::HandshakeFailure,
                },
                error,
            }))
        } else {
            Ok(CommonState::Expect(ExpectState::ServerKeyExchange(
                ExpectServerKeyExchange {
                    suite: self.suite,
                    randoms: self.randoms,
                    transcript: self.transcript,
                },
            )))
        }
    }

    pub(crate) fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}

pub(crate) struct ExpectServerKeyExchange {
    suite: &'static Tls12CipherSuite,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}
impl ExpectServerKeyExchange {
    pub(crate) fn process_message(
        self,
        _common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        let opaque_kx = require_handshake_msg_move!(
            msg,
            HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerKeyExchange
        )?;

        Ok(CommonState::Expect(ExpectState::ServerHelloDone(
            ExpectServerHelloDone {
                suite: self.suite,
                randoms: self.randoms,
                opaque_kx,
                transcript: self.transcript,
            },
        )))
    }

    pub(crate) fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}

pub(crate) struct ExpectServerHelloDone {
    suite: &'static Tls12CipherSuite,
    opaque_kx: ServerKeyExchangePayload,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}

impl ExpectServerHelloDone {
    pub(crate) fn process_message(
        self,
        common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        match msg.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::CertificateRequest,
                        payload: HandshakePayload::CertificateRequest(_),
                    },
                ..
            } => Ok(CommonState::Expect(ExpectState::ServerHelloDone(self))),
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::ServerHelloDone,
                        payload: HandshakePayload::ServerHelloDone,
                    },
                ..
            } => match self
                .opaque_kx
                .unwrap_given_kxa(self.suite.kx)
            {
                Some(ecdhe) => {
                    let mut kx_params = Vec::new();
                    ecdhe.params.encode(&mut kx_params);
                    let server_kx = ServerKxDetails::new(kx_params, ecdhe.dss);

                    let mut rd = Reader::init(&server_kx.kx_params);
                    let ecdh_params = ServerECDHParams::read(&mut rd)?;

                    if rd.any_left() {
                        Ok(CommonState::Write(WriteState::Alert {
                            description: AlertDescription::DecodeError,
                            error: InvalidMessage::InvalidDhParams.into(),
                        }))
                    } else if let Some(skxg) = common
                        .config
                        .find_kx_group(ecdh_params.curve_params.named_group)
                    {
                        let kx = skxg
                            .start()
                            .map_err(|_| Error::FailedToGetRandomBytes)?;

                        Ok(CommonState::Write(WriteState::ClientKeyExchange {
                            suite: self.suite,
                            kx,
                            ecdh_params,
                            randoms: self.randoms,
                            transcript: self.transcript,
                        }))
                    } else {
                        Ok(CommonState::Write(WriteState::Alert {
                            description: AlertDescription::IllegalParameter,
                            error: PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup
                                .into(),
                        }))
                    }
                }
                None => Ok(CommonState::Write(WriteState::Alert {
                    description: AlertDescription::DecodeError,
                    error: InvalidMessage::MissingKeyExchange.into(),
                })),
            },
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

    pub(crate) fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}
