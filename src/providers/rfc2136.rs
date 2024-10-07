/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::net::{AddrParseError, SocketAddr};
use std::sync::Arc;

use hickory_client::client::{Client, ClientHandle};
use hickory_client::ClientError;

use hickory_proto::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_proto::dnssec::rdata::KEY;
use hickory_proto::dnssec::tsig::TSigner;
use hickory_proto::dnssec::{DnsSecError, SigSigner, SigningKey};
use hickory_proto::op::MessageFinalizer;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::ProtoError;

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

use crate::{DnsRecord, Error, IntoFqdn};

#[derive(Clone, Serialize, Deserialize)]
pub struct Rfc2136Config {
    addr: String,
    #[serde(flatten)]
    kind: SignerKind,
}

impl TryFrom<Rfc2136Config> for Rfc2136Provider {
    type Error = Error;

    fn try_from(config: Rfc2136Config) -> crate::Result<Self> {
        match config.kind {
            SignerKind::TSIG(tsig_config) => Self::new_tsig(
                config.addr,
                tsig_config.key_name,
                tsig_config.key,
                tsig_config.algorithm,
            ),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignerKind {
    TSIG(TsigConfig),
    // TODO: Loading a `KeyPair` is tricky, so this is not implemented yet
    // SIG0(Sig0Config),
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct TsigConfig {
    key_name: String,
    #[serde_as(as = "Base64")]
    key: Vec<u8>,
    algorithm: TsigAlgorithm,
}

// #[serde_as]
// #[derive(Deserialize)]
// pub struct Sig0Config {
//     signer_name: String,
//     key: KeyPair<Private>,
//     #[serde_as(as = "Base64")]
//     public_key: Vec<u8>,
//     algorithm: Algorithm,
// }

#[derive(Clone)]
pub struct Rfc2136Provider {
    addr: DnsAddress,
    signer: Arc<dyn MessageFinalizer>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsAddress {
    Tcp(SocketAddr),
    Udp(SocketAddr),
}

impl Rfc2136Provider {
    pub(crate) fn new_tsig(
        addr: impl TryInto<DnsAddress>,
        key_name: impl AsRef<str>,
        key: impl Into<Vec<u8>>,
        algorithm: TsigAlgorithm,
    ) -> crate::Result<Self> {
        Ok(Rfc2136Provider {
            addr: addr
                .try_into()
                .map_err(|_| Error::Parse("Invalid address".to_string()))?,
            signer: Arc::new(TSigner::new(
                key.into(),
                algorithm,
                Name::from_ascii(key_name.as_ref())?,
                60,
            )?),
        })
    }

    pub(crate) fn new_sig0(
        addr: impl TryInto<DnsAddress>,
        signer_name: impl AsRef<str>,
        key: Box<dyn SigningKey>,
        public_key: KEY,
    ) -> crate::Result<Self> {
        let signer = SigSigner::sig0(
            public_key,
            key,
            Name::from_str_relaxed(signer_name.as_ref())?,
        );

        Ok(Rfc2136Provider {
            addr: addr
                .try_into()
                .map_err(|_| Error::Parse("Invalid address".to_string()))?,
            signer: Arc::new(signer),
        })
    }

    async fn connect(&self) -> crate::Result<Client> {
        match &self.addr {
            DnsAddress::Udp(addr) => {
                let stream = UdpClientStream::builder(*addr, TokioRuntimeProvider::new())
                    .with_signer(Some(self.signer.clone()))
                    .build();
                let (client, bg) = Client::connect(stream).await?;
                tokio::spawn(bg);
                Ok(client)
            }
            DnsAddress::Tcp(addr) => {
                let (stream, sender) =
                    TcpClientStream::new(*addr, None, None, TokioRuntimeProvider::new());
                let (client, bg) = Client::new(stream, sender, Some(self.signer.clone())).await?;
                tokio::spawn(bg);
                Ok(client)
            }
        }
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let rdata = convert_record(record)?;
        let record = Record::from_rdata(
            Name::from_str_relaxed(name.into_name().as_ref())?,
            ttl,
            rdata,
        );

        let mut client = self.connect().await?;
        let result = client
            .create(record, Name::from_str_relaxed(origin.into_fqdn().as_ref())?)
            .await?;
        if result.response_code() == ResponseCode::NoError {
            Ok(())
        } else {
            Err(crate::Error::Response(result.response_code().to_string()))
        }
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let rdata = convert_record(record)?;
        let record = Record::from_rdata(
            Name::from_str_relaxed(name.into_name().as_ref())?,
            ttl,
            rdata,
        );

        let mut client = self.connect().await?;
        let result = client
            .append(
                record,
                Name::from_str_relaxed(origin.into_fqdn().as_ref())?,
                false,
            )
            .await?;
        if result.response_code() == ResponseCode::NoError {
            Ok(())
        } else {
            Err(crate::Error::Response(result.response_code().to_string()))
        }
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let mut client = self.connect().await?;
        let result = client
            .delete_all(
                Name::from_str_relaxed(name.into_name().as_ref())?,
                Name::from_str_relaxed(origin.into_fqdn().as_ref())?,
                DNSClass::IN,
            )
            .await?;
        if result.response_code() == ResponseCode::NoError {
            Ok(())
        } else {
            Err(crate::Error::Response(result.response_code().to_string()))
        }
    }
}

fn convert_record(record: DnsRecord) -> crate::Result<RData> {
    Ok(match record {
        DnsRecord::A { content } => RData::A(A::from(content)),
        DnsRecord::AAAA { content } => RData::AAAA(AAAA::from(content)),
        DnsRecord::CNAME { content } => RData::CNAME(CNAME(Name::from_str_relaxed(content)?)),
        DnsRecord::NS { content } => RData::NS(NS(Name::from_str_relaxed(content)?)),
        DnsRecord::MX { content, priority } => {
            RData::MX(MX::new(priority, Name::from_str_relaxed(content)?))
        }
        DnsRecord::TXT { content } => RData::TXT(TXT::new(vec![content])),
        DnsRecord::SRV {
            content,
            priority,
            weight,
            port,
        } => RData::SRV(SRV::new(
            priority,
            weight,
            port,
            Name::from_str_relaxed(content)?,
        )),
    })
}

impl TryFrom<&str> for DnsAddress {
    type Error = ();

    fn try_from(url: &str) -> Result<Self, Self::Error> {
        let (host, is_tcp) = if let Some(host) = url.strip_prefix("udp://") {
            (host, false)
        } else if let Some(host) = url.strip_prefix("tcp://") {
            (host, true)
        } else {
            (url, false)
        };
        let (host, port) = if let Some(host) = host.strip_prefix('[') {
            let (host, maybe_port) = host.rsplit_once(']').ok_or(())?;

            (
                host,
                maybe_port
                    .rsplit_once(':')
                    .map(|(_, port)| port)
                    .unwrap_or("53"),
            )
        } else if let Some((host, port)) = host.rsplit_once(':') {
            (host, port)
        } else {
            (host, "53")
        };

        let addr = SocketAddr::new(host.parse().map_err(|_| ())?, port.parse().map_err(|_| ())?);

        if is_tcp {
            Ok(DnsAddress::Tcp(addr))
        } else {
            Ok(DnsAddress::Udp(addr))
        }
    }
}

impl TryFrom<&String> for DnsAddress {
    type Error = ();

    fn try_from(url: &String) -> Result<Self, Self::Error> {
        DnsAddress::try_from(url.as_str())
    }
}

impl TryFrom<String> for DnsAddress {
    type Error = ();

    fn try_from(url: String) -> Result<Self, Self::Error> {
        DnsAddress::try_from(url.as_str())
    }
}

impl From<crate::TsigAlgorithm> for TsigAlgorithm {
    fn from(alg: crate::TsigAlgorithm) -> Self {
        match alg {
            crate::TsigAlgorithm::HmacMd5 => TsigAlgorithm::HmacMd5,
            crate::TsigAlgorithm::Gss => TsigAlgorithm::Gss,
            crate::TsigAlgorithm::HmacSha1 => TsigAlgorithm::HmacSha1,
            crate::TsigAlgorithm::HmacSha224 => TsigAlgorithm::HmacSha224,
            crate::TsigAlgorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
            crate::TsigAlgorithm::HmacSha256_128 => TsigAlgorithm::HmacSha256_128,
            crate::TsigAlgorithm::HmacSha384 => TsigAlgorithm::HmacSha384,
            crate::TsigAlgorithm::HmacSha384_192 => TsigAlgorithm::HmacSha384_192,
            crate::TsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
            crate::TsigAlgorithm::HmacSha512_256 => TsigAlgorithm::HmacSha512_256,
        }
    }
}

impl From<crate::Algorithm> for Algorithm {
    fn from(alg: crate::Algorithm) -> Self {
        match alg {
            crate::Algorithm::RSASHA256 => Algorithm::RSASHA256,
            crate::Algorithm::RSASHA512 => Algorithm::RSASHA512,
            crate::Algorithm::ECDSAP256SHA256 => Algorithm::ECDSAP256SHA256,
            crate::Algorithm::ECDSAP384SHA384 => Algorithm::ECDSAP384SHA384,
            crate::Algorithm::ED25519 => Algorithm::ED25519,
        }
    }
}

impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Self {
        Error::Protocol(e.to_string())
    }
}

impl From<AddrParseError> for Error {
    fn from(e: AddrParseError) -> Self {
        Error::Parse(e.to_string())
    }
}

impl From<ClientError> for Error {
    fn from(e: ClientError) -> Self {
        Error::Client(e.to_string())
    }
}

impl From<DnsSecError> for Error {
    fn from(e: DnsSecError) -> Self {
        Error::DnsSec(e.to_string())
    }
}
