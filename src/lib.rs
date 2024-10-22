#![doc = include_str!("../README.md")]
use core::fmt;
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
use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    time::Duration,
};

use hickory_client::proto::dnssec::{rdata::KEY, SigningKey};
pub use hickory_proto::rr::rdata::A;
pub use hickory_proto::rr::rdata::AAAA;
pub use hickory_proto::rr::RData;
use providers::{
    cloudflare::{CloudflareConfig, CloudflareProvider},
    rfc2136::{DnsAddress, Rfc2136Config, Rfc2136Provider},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod http;
pub mod providers;

pub use hickory_proto::dnssec::{rdata::tsig::TsigAlgorithm, Algorithm};

#[derive(Debug, Error)]
pub enum Error {
    Protocol(String),
    Parse(String),
    Client(String),
    Response(String),
    Api(String),
    Serialize(String),
    Unauthorized,
    NotFound,
    DnsSec(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsUpdaterConfig {
    Rfc2136(Rfc2136Config),
    Cloudflare(CloudflareConfig),
}

impl TryFrom<DnsUpdaterConfig> for DnsUpdater {
    type Error = crate::Error;

    fn try_from(config: DnsUpdaterConfig) -> Result<Self> {
        match config {
            DnsUpdaterConfig::Rfc2136(rfc2136_config) => {
                Ok(DnsUpdater::Rfc2136(rfc2136_config.try_into()?))
            }
            DnsUpdaterConfig::Cloudflare(cloudflare_config) => {
                Ok(DnsUpdater::Cloudflare(cloudflare_config.into()))
            }
        }
    }
}

#[derive(Clone)]
pub enum DnsUpdater {
    Rfc2136(Rfc2136Provider),
    Cloudflare(CloudflareProvider),
}

pub trait IntoFqdn<'x> {
    fn into_fqdn(self) -> Cow<'x, str>;
    fn into_name(self) -> Cow<'x, str>;
}

impl DnsUpdater {
    /// Create a new DNS updater using the RFC 2136 protocol and TSIG authentication.
    pub fn new_rfc2136_tsig(
        addr: impl TryInto<DnsAddress>,
        key_name: impl AsRef<str>,
        key: impl Into<Vec<u8>>,
        algorithm: TsigAlgorithm,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Rfc2136(Rfc2136Provider::new_tsig(
            addr,
            key_name,
            key,
            algorithm.into(),
        )?))
    }

    /// Create a new DNS updater using the RFC 2136 protocol and SIG(0) authentication.
    pub fn new_rfc2136_sig0(
        addr: impl TryInto<DnsAddress>,
        signer_name: impl AsRef<str>,
        key: Box<dyn SigningKey>,
        public_key: KEY,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Rfc2136(Rfc2136Provider::new_sig0(
            addr,
            signer_name,
            key,
            public_key,
        )?))
    }

    /// Create a new DNS updater using the Cloudflare API.
    pub fn new_cloudflare(
        secret: impl AsRef<str>,
        email: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> Self {
        DnsUpdater::Cloudflare(CloudflareProvider::new(secret, email, timeout))
    }

    /// Create a new DNS record.
    pub async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: RData,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Rfc2136(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Cloudflare(provider) => provider.create(name, record, ttl, origin).await,
        }
    }

    /// Update an existing DNS record.
    pub async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: RData,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Rfc2136(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Cloudflare(provider) => provider.update(name, record, ttl, origin).await,
        }
    }

    /// Delete an existing DNS record.
    pub async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Rfc2136(provider) => provider.delete(name, origin).await,
            DnsUpdater::Cloudflare(provider) => provider.delete(name, origin).await,
        }
    }
}

impl<'x> IntoFqdn<'x> for &'x str {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            Cow::Borrowed(self)
        } else {
            Cow::Owned(format!("{}.", self))
        }
    }

    fn into_name(self) -> Cow<'x, str> {
        if let Some(name) = self.strip_suffix('.') {
            Cow::Borrowed(name)
        } else {
            Cow::Borrowed(self)
        }
    }
}

impl<'x> IntoFqdn<'x> for &'x String {
    fn into_fqdn(self) -> Cow<'x, str> {
        self.as_str().into_fqdn()
    }

    fn into_name(self) -> Cow<'x, str> {
        self.as_str().into_name()
    }
}

impl<'x> IntoFqdn<'x> for String {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            Cow::Owned(self)
        } else {
            Cow::Owned(format!("{}.", self))
        }
    }

    fn into_name(self) -> Cow<'x, str> {
        if let Some(name) = self.strip_suffix('.') {
            Cow::Owned(name.to_string())
        } else {
            Cow::Owned(self)
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protocol(e) => write!(f, "Protocol error: {}", e),
            Error::Parse(e) => write!(f, "Parse error: {}", e),
            Error::Client(e) => write!(f, "Client error: {}", e),
            Error::DnsSec(e) => write!(f, "DNSSEC error: {}", e),
            Error::Response(e) => write!(f, "Response error: {}", e),
            Error::Api(e) => write!(f, "API error: {}", e),
            Error::Serialize(e) => write!(f, "Serialize error: {}", e),
            Error::Unauthorized => write!(f, "Unauthorized"),
            Error::NotFound => write!(f, "Not found"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::DnsUpdaterConfig;

    #[test]
    fn provider_config() {
        let cloudflare_config_string = r###"{
            "cloudflare": {
                "secret": "<put_token_here>"
            }
        }"###;
        let _cloudflare_config: DnsUpdaterConfig =
            serde_json::from_str(&cloudflare_config_string).unwrap();

        let rfc2136_config_string = r###"{
            "rfc2136": {
                "addr": "udp://1.2.3.4:53",
                "key_name": "test",
                "key": "test",
                "algorithm": "hmac-sha256"
            }
        }"###;
        let _rfc2136_config: DnsUpdaterConfig =
            serde_json::from_str(&rfc2136_config_string).unwrap();
    }
}
