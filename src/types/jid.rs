// src/types/jid.rs
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

// Constants
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

// Type Aliases
pub type MessageId = String;
pub type MessageServerId = i32;

#[derive(Debug, Error)]
pub enum JidError {
    #[error("Invalid JID format: {0}")]
    InvalidFormat(String),
    #[error("Failed to parse component: {0}")]
    Parse(#[from] std::num::ParseIntError),
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

    pub fn is_ad(&self) -> bool {
        self.device > 0
            && (self.server == DEFAULT_USER_SERVER
                || self.server == HIDDEN_USER_SERVER
                || self.server == HOSTED_SERVER)
    }

    pub fn is_interop(&self) -> bool {
        self.server == INTEROP_SERVER && self.integrator > 0
    }

    pub fn is_messenger(&self) -> bool {
        self.server == MESSENGER_SERVER && self.device > 0
    }

    pub fn is_group(&self) -> bool {
        self.server == GROUP_SERVER
    }

    pub fn is_broadcast_list(&self) -> bool {
        self.server == BROADCAST_SERVER && self.user != STATUS_BROADCAST_USER
    }

    pub fn is_bot(&self) -> bool {
        (self.server == DEFAULT_USER_SERVER
            && self.device == 0
            && (self.user.starts_with("1313555") || self.user.starts_with("131655500")))
            || self.server == BOT_SERVER
    }

    pub fn is_empty(&self) -> bool {
        self.server.is_empty()
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
            let mut user_part = self.user.clone();
            if self.agent > 0 {
                user_part.push('.');
                user_part.push_str(&self.agent.to_string());
            }
            if self.device > 0 {
                user_part.push(':');
                user_part.push_str(&self.device.to_string());
            }
            write!(f, "{}@{}", user_part, self.server)
        }
    }
}

impl From<Jid> for String {
    fn from(jid: Jid) -> Self {
        jid.to_string()
    }
}

impl TryFrom<String> for Jid {
    type Error = JidError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Jid::from_str(&value)
    }
}
