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

        let known_servers = [
            DEFAULT_USER_SERVER,
            GROUP_SERVER,
            LEGACY_USER_SERVER,
            BROADCAST_SERVER,
            HIDDEN_USER_SERVER,
            NEWSLETTER_SERVER,
            HOSTED_SERVER,
            MESSENGER_SERVER,
            INTEROP_SERVER,
            BOT_SERVER,
            STATUS_BROADCAST_USER,
        ];

        if user_part.is_empty() {
            if s.contains('@') {
                if server.is_empty() {
                    return Err(JidError::InvalidFormat(
                        "Invalid JID format: missing server".to_string(),
                    ));
                }
                if !known_servers.contains(&server.as_str()) {
                    return Err(JidError::InvalidFormat(format!(
                        "Invalid JID format: unknown server '{}'",
                        server
                    )));
                }
                // Allow empty user parts when an '@' is present (e.g. "@g.us").
            } else if !known_servers.contains(&server.as_str()) {
                return Err(JidError::InvalidFormat(format!(
                    "Invalid JID format: unknown server '{}'",
                    server
                )));
            }
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
        }

        if server != DEFAULT_USER_SERVER
            && server != HIDDEN_USER_SERVER
            && let Some((u, last_part)) = user.rsplit_once('.')
            && let Ok(num_val) = last_part.parse::<u16>()
        {
            user = u;
            agent = num_val as u8;
        }

        if let Some((u, last_part)) = user_part.rsplit_once('.')
            && let Ok(num_val) = last_part.parse::<u16>()
        {
            if server == DEFAULT_USER_SERVER {
                user = u;
                device = num_val;
            } else {
                user = u;
                if num_val > u8::MAX as u16 {
                    return Err(JidError::InvalidFormat(format!(
                        "Agent component out of range: {num_val}"
                    )));
                }
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

            // The agent is encoded in the server type for AD JIDs.
            // We should NOT append it to the user string for standard servers.
            // Only non-standard servers might use an agent suffix.
            // The old JS logic appears to never append the agent for s.whatsapp.net or lid.
            if self.agent > 0 {
                // This is a guess based on the failure. The old JS logic is complex.
                // We will only append the agent if the server is NOT s.whatsapp.net or lid.
                // AND the server is not one that is derived *from* the agent (like 'hosted').
                let server_str = self.server(); // Use trait method
                if server_str != DEFAULT_USER_SERVER
                    && server_str != HIDDEN_USER_SERVER
                    && server_str != HOSTED_SERVER
                {
                    write!(f, ".{}", self.agent)?;
                }
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

            // The agent is encoded in the server type for AD JIDs.
            // We should NOT append it to the user string for standard servers.
            // Only non-standard servers might use an agent suffix.
            // The old JS logic appears to never append the agent for s.whatsapp.net or lid.
            if self.agent > 0 {
                // This is a guess based on the failure. The old JS logic is complex.
                // We will only append the agent if the server is NOT s.whatsapp.net or lid.
                // AND the server is not one that is derived *from* the agent (like 'hosted').
                let server_str = self.server(); // Use trait method
                if server_str != DEFAULT_USER_SERVER
                    && server_str != HIDDEN_USER_SERVER
                    && server_str != HOSTED_SERVER
                {
                    write!(f, ".{}", self.agent)?;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Helper function to test a full parsing and display round-trip.
    fn assert_jid_roundtrip(
        input: &str,
        expected_user: &str,
        expected_server: &str,
        expected_device: u16,
        expected_agent: u8,
    ) {
        // 1. Test parsing from string (FromStr trait)
        let jid = Jid::from_str(input).unwrap_or_else(|_| panic!("Failed to parse JID: {}", input));

        assert_eq!(
            jid.user, expected_user,
            "User part did not match for {}",
            input
        );
        assert_eq!(
            jid.server, expected_server,
            "Server part did not match for {}",
            input
        );
        assert_eq!(
            jid.device, expected_device,
            "Device part did not match for {}",
            input
        );
        assert_eq!(
            jid.agent, expected_agent,
            "Agent part did not match for {}",
            input
        );

        // 2. Test formatting back to string (Display trait)
        let formatted = jid.to_string();
        assert_eq!(
            formatted, input,
            "Formatted string did not match original input"
        );
    }

    #[test]
    fn test_jid_parsing_and_display_roundtrip() {
        // Standard cases
        assert_jid_roundtrip(
            "1234567890@s.whatsapp.net",
            "1234567890",
            "s.whatsapp.net",
            0,
            0,
        );
        assert_jid_roundtrip(
            "1234567890:15@s.whatsapp.net",
            "1234567890",
            "s.whatsapp.net",
            15,
            0,
        );
        assert_jid_roundtrip("123-456@g.us", "123-456", "g.us", 0, 0);
        assert_jid_roundtrip("s.whatsapp.net", "", "s.whatsapp.net", 0, 0);

        // LID JID cases (critical for the bug)
        assert_jid_roundtrip("12345.6789@lid", "12345.6789", "lid", 0, 0);
        assert_jid_roundtrip("12345.6789:25@lid", "12345.6789", "lid", 25, 0);
    }

    #[test]
    fn test_special_from_str_parsing() {
        // Test parsing of JIDs with an agent, which should be stored in the struct
        let jid = Jid::from_str("1234567890.2:15@hosted").unwrap();
        assert_eq!(jid.user, "1234567890");
        assert_eq!(jid.server, "hosted");
        assert_eq!(jid.device, 15);
        assert_eq!(jid.agent, 2);
    }

    #[test]
    fn test_allow_empty_user_with_known_server() {
        let group_jid = Jid::from_str("@g.us").unwrap();
        assert_eq!(group_jid.user, "");
        assert_eq!(group_jid.server, GROUP_SERVER);

        let default_server_jid = Jid::from_str("@s.whatsapp.net").unwrap();
        assert_eq!(default_server_jid.user, "");
        assert_eq!(default_server_jid.server, DEFAULT_USER_SERVER);
    }

    #[test]
    fn test_manual_jid_formatting_edge_cases() {
        // This test directly validates the fixes for the parity failures.
        // We manually construct the Jid struct as the binary decoder would,
        // then we assert that its string representation is correct.

        // Failure Case 1: An AD-JID for s.whatsapp.net decoded with an agent.
        // The Display trait MUST NOT show the agent number.
        let jid1 = Jid {
            user: "1234567890".to_string(),
            server: "s.whatsapp.net".to_string(),
            device: 15,
            agent: 2, // This agent would be decoded from binary but should be ignored in display
            integrator: 0,
        };
        // Expected: "1234567890:15@s.whatsapp.net" (agent is omitted)
        // Buggy: "1234567890.2:15@s.whatsapp.net"
        assert_eq!(jid1.to_string(), "1234567890:15@s.whatsapp.net");

        // Failure Case 2: A LID JID with a device, decoded with an agent.
        // The Display trait MUST NOT show the agent number.
        let jid2 = Jid {
            user: "12345.6789".to_string(),
            server: "lid".to_string(),
            device: 25,
            agent: 1, // This agent would be decoded from binary but should be ignored in display
            integrator: 0,
        };
        // Expected: "12345.6789:25@lid"
        // Buggy: "12345.6789.1:25@lid"
        assert_eq!(jid2.to_string(), "12345.6789:25@lid");

        // Failure Case 3: A JID that was decoded as "hosted" because of its agent.
        // The Display trait MUST NOT show the agent number.
        let jid3 = Jid {
            user: "1234567890".to_string(),
            server: "hosted".to_string(),
            device: 15,
            agent: 2,
            integrator: 0,
        };
        // Expected: "1234567890:15@hosted"
        // Buggy: "1234567890.2:15@hosted"
        assert_eq!(jid3.to_string(), "1234567890:15@hosted");

        // Verification Case: A generic JID where the agent SHOULD be displayed.
        let jid4 = Jid {
            user: "user".to_string(),
            server: "custom.net".to_string(),
            device: 10,
            agent: 5,
            integrator: 0,
        };
        // The agent should be displayed because the server is not a special AD-JID type
        assert_eq!(jid4.to_string(), "user.5:10@custom.net");
    }

    #[test]
    fn test_invalid_jids_should_fail_to_parse() {
        assert!(Jid::from_str("thisisnotajid").is_err());
        assert!(Jid::from_str("").is_err());
        assert!(Jid::from_str("@").is_err());
        assert!(Jid::from_str("@unknown.server").is_err());
        // Jid::from_str("2") should not be possible due to type constraints,
        // but if it were, it should fail. The string must contain '@'.
        assert!(Jid::from_str("2").is_err());
    }
}
