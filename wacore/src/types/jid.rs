use crate::libsignal::protocol::ProtocolAddress;
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

pub const DEFAULT_USER_SERVER: &str = "s.whatsapp.net";
pub const SERVER_JID: &str = "s.whatsapp.net";
pub const GROUP_SERVER: &str = "g.us";
pub const LEGACY_USER_SERVER: &str = "c.us";
pub const BROADCAST_SERVER: &str = "broadcast";
pub const HIDDEN_USER_SERVER: &str = "lid";
pub const NEWSLETTER_SERVER: &str = "newsletter";
pub const HOSTED_SERVER: &str = "hosted";
pub const MESSENGER_SERVER: &str = "msgr";
pub const INTEROP_SERVER: &str = "interop";
pub const BOT_SERVER: &str = "bot";
pub const STATUS_BROADCAST_USER: &str = "status";

pub type MessageId = String;
pub type MessageServerId = i32;

#[derive(Debug, Error)]
pub enum JidError {
    #[error("Invalid JID format: {0}")]
    InvalidFormat(String),
    #[error("Failed to parse component: {0}")]
    Parse(#[from] std::num::ParseIntError),
}

pub trait JidExt {
    fn user(&self) -> &str;
    fn server(&self) -> &str;
    fn device(&self) -> u16;
    fn integrator(&self) -> u16;

    fn is_ad(&self) -> bool {
        self.device() > 0
            && (self.server() == DEFAULT_USER_SERVER
                || self.server() == HIDDEN_USER_SERVER
                || self.server() == HOSTED_SERVER)
    }

    fn is_interop(&self) -> bool {
        self.server() == INTEROP_SERVER && self.integrator() > 0
    }

    fn is_messenger(&self) -> bool {
        self.server() == MESSENGER_SERVER && self.device() > 0
    }

    fn is_group(&self) -> bool {
        self.server() == GROUP_SERVER
    }

    fn is_broadcast_list(&self) -> bool {
        self.server() == BROADCAST_SERVER && self.user() != STATUS_BROADCAST_USER
    }

    fn is_bot(&self) -> bool {
        (self.server() == DEFAULT_USER_SERVER
            && self.device() == 0
            && (self.user().starts_with("1313555") || self.user().starts_with("131655500")))
            || self.server() == BOT_SERVER
    }

    fn is_empty(&self) -> bool {
        self.server().is_empty()
    }

    fn is_same_user_as(&self, other: &impl JidExt) -> bool {
        self.user() == other.user()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Jid {
    pub user: String,
    pub server: String,
    pub agent: u8,
    pub device: u16,
    pub integrator: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JidRef<'a> {
    pub user: Cow<'a, str>,
    pub server: Cow<'a, str>,
    pub agent: u8,
    pub device: u16,
    pub integrator: u16,
}

impl JidExt for Jid {
    fn user(&self) -> &str {
        &self.user
    }
    fn server(&self) -> &str {
        &self.server
    }
    fn device(&self) -> u16 {
        self.device
    }
    fn integrator(&self) -> u16 {
        self.integrator
    }
}

impl Jid {
    pub fn new(user: &str, server: &str) -> Self {
        Self {
            user: user.to_string(),
            server: server.to_string(),
            ..Default::default()
        }
    }

    pub fn to_non_ad(&self) -> Self {
        Self {
            user: self.user.clone(),
            server: self.server.clone(),
            integrator: self.integrator,
            ..Default::default()
        }
    }

    pub fn to_ad_string(&self) -> String {
        if self.user.is_empty() {
            self.server.clone()
        } else {
            format!(
                "{}.{}:{}@{}",
                self.user, self.agent, self.device, self.server
            )
        }
    }

    pub fn to_protocol_address(&self) -> ProtocolAddress {
        ProtocolAddress::new(self.user.clone(), (self.device as u32).into())
    }
}

impl<'a> JidExt for JidRef<'a> {
    fn user(&self) -> &str {
        &self.user
    }
    fn server(&self) -> &str {
        &self.server
    }
    fn device(&self) -> u16 {
        self.device
    }
    fn integrator(&self) -> u16 {
        self.integrator
    }
}

impl<'a> JidRef<'a> {
    pub fn new(user: Cow<'a, str>, server: Cow<'a, str>) -> Self {
        Self {
            user,
            server,
            agent: 0,
            device: 0,
            integrator: 0,
        }
    }

    pub fn to_owned(&self) -> Jid {
        Jid {
            user: self.user.to_string(),
            server: self.server.to_string(),
            agent: self.agent,
            device: self.device,
            integrator: self.integrator,
        }
    }
}

impl FromStr for Jid {
    type Err = JidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (user_part, server) = match s.split_once('@') {
            Some((u, s)) => (u, s.to_string()),
            None => ("", s.to_string()),
        };

        if user_part.is_empty() {
            return Ok(Jid::new("", &server));
        }

        let (user_base, device_str) = match user_part.rsplit_once(':') {
            Some((u, d)) => (u, Some(d)),
            None => (user_part, None),
        };

        let (user, agent_str) = match user_base.rsplit_once('.') {
            Some((u, a)) => (u, Some(a)),
            None => (user_base, None),
        };

        let agent = if let Some(a_str) = agent_str {
            a_str.parse()?
        } else {
            0
        };
        let device = if let Some(d_str) = device_str {
            d_str.parse()?
        } else {
            0
        };

        Ok(Jid {
            user: user.to_string(),
            server,
            agent,
            device,
            integrator: 0,
        })
    }
}

impl fmt::Display for Jid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.user.is_empty() {
            write!(f, "{}", self.server)
        } else {
            write!(f, "{}", self.user)?;
            if self.agent > 0 {
                write!(f, ".{}", self.agent)?;
            }
            if self.device > 0 {
                write!(f, ":{}", self.device)?;
            }
            write!(f, "@{}", self.server)
        }
    }
}

impl<'a> fmt::Display for JidRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.user.is_empty() {
            write!(f, "{}", self.server)
        } else {
            write!(f, "{}", self.user)?;
            if self.agent > 0 {
                write!(f, ".{}", self.agent)?;
            }
            if self.device > 0 {
                write!(f, ":{}", self.device)?;
            }
            write!(f, "@{}", self.server)
        }
    }
}

impl From<Jid> for String {
    fn from(jid: Jid) -> Self {
        jid.to_string()
    }
}

impl<'a> From<JidRef<'a>> for String {
    fn from(jid: JidRef<'a>) -> Self {
        jid.to_string()
    }
}

impl TryFrom<String> for Jid {
    type Error = JidError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Jid::from_str(&value)
    }
}
