use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

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
#[derive(Debug)]
pub enum JidError {
    // REMOVE: #[error("...")]
    InvalidFormat(String),
    // REMOVE: #[error("...")]
    Parse(std::num::ParseIntError),
}

impl fmt::Display for JidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JidError::InvalidFormat(s) => write!(f, "Invalid JID format: {s}"),
            JidError::Parse(e) => write!(f, "Failed to parse component: {e}"),
        }
    }
}

impl std::error::Error for JidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JidError::Parse(e) => Some(e),
            _ => None,
        }
    }
}

// Add From impl
impl From<std::num::ParseIntError> for JidError {
    fn from(err: std::num::ParseIntError) -> Self {
        JidError::Parse(err)
    }
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

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
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

    pub fn actual_agent(&self) -> u8 {
        match self.server.as_str() {
            DEFAULT_USER_SERVER => 0,
            // For LID (HIDDEN_USER_SERVER), use the parsed agent value.
            // LID user identifiers can contain dots (e.g., "236395184570386.1"),
            // which are part of the identity, not agent separators.
            // Only non-device LID JIDs (without ':') may have an agent suffix.
            HIDDEN_USER_SERVER => self.agent,
            _ => self.agent,
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

        // Special handling for LID JIDs, as their user part can contain dots
        // that should not be interpreted as agent separators.
        if server == HIDDEN_USER_SERVER {
            let (user, device) = if let Some((u, d_str)) = user_part.rsplit_once(':') {
                (u, d_str.parse()?)
            } else {
                (user_part, 0)
            };
            return Ok(Jid {
                user: user.to_string(),
                server,
                device,
                agent: 0,
                integrator: 0,
            });
        }

        // Fallback to existing logic for other JID types (s.whatsapp.net, etc.)
        let mut user = user_part;
        let mut device = 0;
        let mut agent = 0;

        if let Some((u, d_str)) = user_part.rsplit_once(':') {
            user = u;
            device = d_str.parse()?;
        } else if let Some((u, last_part)) = user_part.rsplit_once('.')
            && let Ok(num_val) = last_part.parse::<u16>()
        {
            if server == DEFAULT_USER_SERVER {
                user = u;
                device = num_val;
            } else {
                user = u;
                agent = num_val as u8;
            }
        }

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
