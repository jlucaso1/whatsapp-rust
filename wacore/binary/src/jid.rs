use crate::node::NodeStr;
use compact_str::CompactString;
use std::fmt;
use std::str::FromStr;

/// Intermediate result from fast JID parsing.
/// This avoids allocations by returning byte indices into the original string.
#[derive(Debug, Clone, Copy)]
pub struct ParsedJidParts<'a> {
    pub user: &'a str,
    pub server: &'a str,
    pub agent: u8,
    pub device: u16,
    pub integrator: u16,
}

/// Single-pass JID parser optimized for hot paths.
/// Scans the input string once to find all relevant separators (@, :)
/// and returns slices into the original string without allocation.
///
/// Returns `None` for JIDs that need full validation (edge cases, unknown servers, etc.)
#[inline]
pub fn parse_jid_fast(s: &str) -> Option<ParsedJidParts<'_>> {
    if s.is_empty() {
        return None;
    }

    let bytes = s.as_bytes();

    // Single pass to find key separator positions
    let mut at_pos: Option<usize> = None;
    let mut colon_pos: Option<usize> = None;
    let mut last_dot_pos: Option<usize> = None;

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'@' if at_pos.is_none() => at_pos = Some(i),
            // Only track colon in user part (before @)
            b':' if at_pos.is_none() => colon_pos = Some(i),
            // Only track dots in user part (before @ and before :)
            b'.' if at_pos.is_none() && colon_pos.is_none() => last_dot_pos = Some(i),
            _ => {}
        }
    }

    // Extract at_pos as concrete value - after this point we know @ exists
    let at = match at_pos {
        Some(pos) => pos,
        None => {
            // Server-only JID - let the fallback validate it
            return None;
        }
    };

    let user_part = &s[..at];
    let server = &s[at + 1..];

    // Validate that user_part is not empty
    if user_part.is_empty() {
        return None;
    }

    // Fast path for LID JIDs - dots in user are not agent separators
    if server == HIDDEN_USER_SERVER {
        let (user, device) = match colon_pos {
            Some(pos) if pos < at => {
                let device_slice = &s[pos + 1..at];
                (&s[..pos], device_slice.parse::<u16>().unwrap_or(0))
            }
            _ => (user_part, 0),
        };
        return Some(ParsedJidParts {
            user,
            server,
            agent: 0,
            device,
            integrator: 0,
        });
    }

    // For DEFAULT_USER_SERVER (s.whatsapp.net), handle legacy dot format as device
    if server == DEFAULT_USER_SERVER {
        // Check for colon format first (modern: user:device@server)
        if let Some(pos) = colon_pos {
            let user_end = pos;
            let device_start = pos + 1;
            let device_slice = &s[device_start..at];
            let device = device_slice.parse::<u16>().unwrap_or(0);
            return Some(ParsedJidParts {
                user: &s[..user_end],
                server,
                agent: 0,
                device,
                integrator: 0,
            });
        }
        // Check for legacy dot format (legacy: user.device@server)
        if let Some(dot_pos) = last_dot_pos {
            // dot_pos is absolute position in s
            let suffix = &s[dot_pos + 1..at];
            if let Ok(device_val) = suffix.parse::<u16>() {
                return Some(ParsedJidParts {
                    user: &s[..dot_pos],
                    server,
                    agent: 0,
                    device: device_val,
                    integrator: 0,
                });
            }
        }
        // No device component
        return Some(ParsedJidParts {
            user: user_part,
            server,
            agent: 0,
            device: 0,
            integrator: 0,
        });
    }

    // Parse device from colon separator (user:device@server)
    let (user_before_colon, device) = match colon_pos {
        Some(pos) => {
            // Colon is at `pos` in the original string
            let user_end = pos;
            let device_start = pos + 1;
            let device_slice = &s[device_start..at];
            (&s[..user_end], device_slice.parse::<u16>().unwrap_or(0))
        }
        None => (user_part, 0),
    };

    // Parse agent from last dot in user part (for non-default, non-LID servers)
    let user_to_check = user_before_colon;
    let (final_user, agent) = {
        if let Some(dot_pos) = user_to_check.rfind('.') {
            let suffix = &user_to_check[dot_pos + 1..];
            if let Ok(agent_val) = suffix.parse::<u16>() {
                if agent_val <= u8::MAX as u16 {
                    (&user_to_check[..dot_pos], agent_val as u8)
                } else {
                    (user_to_check, 0)
                }
            } else {
                (user_to_check, 0)
            }
        } else {
            (user_to_check, 0)
        }
    };

    Some(ParsedJidParts {
        user: final_user,
        server,
        agent,
        device,
        integrator: 0,
    })
}

/// Known WhatsApp server identifiers.
///
/// Maps to the wire protocol's AD_JID domain type (u8) and the `@server` suffix
/// in JID string representation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Server {
    #[default]
    Pn = 0,
    Lid = 1,
    Group = 2,
    Broadcast = 3,
    Newsletter = 4,
    Hosted = 5,
    HostedLid = 6,
    Messenger = 7,
    Interop = 8,
    Bot = 9,
    Legacy = 10,
}

#[cfg(feature = "serde")]
impl serde::Serialize for Server {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Server {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        Server::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Server {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pn => "s.whatsapp.net",
            Self::Lid => "lid",
            Self::Group => "g.us",
            Self::Broadcast => "broadcast",
            Self::Newsletter => "newsletter",
            Self::Hosted => "hosted",
            Self::HostedLid => "hosted.lid",
            Self::Messenger => "msgr",
            Self::Interop => "interop",
            Self::Bot => "bot",
            Self::Legacy => "c.us",
        }
    }

    /// Phone-number-namespaced servers (`@s.whatsapp.net`, `@hosted`).
    /// The PN side of the LID↔PN mapping treats these as a single class.
    #[inline]
    pub fn is_pn_family(self) -> bool {
        matches!(self, Self::Pn | Self::Hosted)
    }

    /// LID-namespaced servers (`@lid`, `@hosted.lid`).
    #[inline]
    pub fn is_lid_family(self) -> bool {
        matches!(self, Self::Lid | Self::HostedLid)
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for Server {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Server {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl TryFrom<&str> for Server {
    type Error = JidError;
    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        match s {
            "s.whatsapp.net" => Ok(Self::Pn),
            "lid" => Ok(Self::Lid),
            "g.us" => Ok(Self::Group),
            "broadcast" => Ok(Self::Broadcast),
            "newsletter" => Ok(Self::Newsletter),
            "hosted" => Ok(Self::Hosted),
            "hosted.lid" => Ok(Self::HostedLid),
            "msgr" => Ok(Self::Messenger),
            "interop" => Ok(Self::Interop),
            "bot" => Ok(Self::Bot),
            "c.us" => Ok(Self::Legacy),
            other => Err(JidError::InvalidFormat(format!("unknown server: {other}"))),
        }
    }
}

// Keep string constants for backward compatibility and use in non-JID contexts
pub const DEFAULT_USER_SERVER: &str = "s.whatsapp.net";
pub const SERVER_JID: &str = "s.whatsapp.net";
pub const GROUP_SERVER: &str = "g.us";
pub const LEGACY_USER_SERVER: &str = "c.us";
pub const BROADCAST_SERVER: &str = "broadcast";
pub const HIDDEN_USER_SERVER: &str = "lid";
pub const NEWSLETTER_SERVER: &str = "newsletter";
pub const HOSTED_SERVER: &str = "hosted";
pub const HOSTED_LID_SERVER: &str = "hosted.lid";
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
    fn server(&self) -> Server;
    fn device(&self) -> u16;
    fn integrator(&self) -> u16;

    fn is_ad(&self) -> bool {
        self.device() > 0
            && matches!(
                self.server(),
                Server::Pn | Server::Lid | Server::Hosted | Server::HostedLid
            )
    }

    fn is_interop(&self) -> bool {
        self.server() == Server::Interop && self.integrator() > 0
    }

    fn is_messenger(&self) -> bool {
        self.server() == Server::Messenger && self.device() > 0
    }

    fn is_group(&self) -> bool {
        self.server() == Server::Group
    }

    fn is_broadcast_list(&self) -> bool {
        self.server() == Server::Broadcast && self.user() != STATUS_BROADCAST_USER
    }

    fn is_status_broadcast(&self) -> bool {
        self.server() == Server::Broadcast && self.user() == STATUS_BROADCAST_USER
    }

    fn is_bot(&self) -> bool {
        (self.server() == Server::Pn
            && self.device() == 0
            && (self.user().starts_with("1313555") || self.user().starts_with("131655500")))
            || self.server() == Server::Bot
    }

    fn is_newsletter(&self) -> bool {
        self.server() == Server::Newsletter
    }

    /// Returns true if this is a hosted/Cloud API device.
    /// Hosted devices have device ID 99 or use @hosted/@hosted.lid server.
    /// These devices should be excluded from group message fanout.
    fn is_hosted(&self) -> bool {
        self.device() == 99 || matches!(self.server(), Server::Hosted | Server::HostedLid)
    }

    fn is_empty(&self) -> bool {
        self.user().is_empty()
    }

    fn is_same_user_as(&self, other: &impl JidExt) -> bool {
        self.user() == other.user()
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Jid {
    pub user: CompactString,
    pub server: Server,
    pub agent: u8,
    pub device: u16,
    pub integrator: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, yoke::Yokeable)]
pub struct JidRef<'a> {
    pub user: NodeStr<'a>,
    pub server: Server,
    pub agent: u8,
    pub device: u16,
    pub integrator: u16,
}

impl JidExt for Jid {
    fn user(&self) -> &str {
        &self.user
    }
    fn server(&self) -> Server {
        self.server
    }
    fn device(&self) -> u16 {
        self.device
    }
    fn integrator(&self) -> u16 {
        self.integrator
    }
}

impl Jid {
    pub fn new(user: impl Into<CompactString>, server: Server) -> Self {
        Self {
            user: user.into(),
            server,
            ..Default::default()
        }
    }

    /// Create a phone number JID (s.whatsapp.net)
    pub fn pn(user: impl Into<CompactString>) -> Self {
        Self {
            user: user.into(),
            server: Server::Pn,
            ..Default::default()
        }
    }

    /// Create a LID JID (lid server)
    pub fn lid(user: impl Into<CompactString>) -> Self {
        Self {
            user: user.into(),
            server: Server::Lid,
            ..Default::default()
        }
    }

    /// Creates the `status@broadcast` JID used for status/story updates.
    pub fn status_broadcast() -> Self {
        Self {
            user: CompactString::from(STATUS_BROADCAST_USER),
            server: Server::Broadcast,
            agent: 0,
            device: 0,
            integrator: 0,
        }
    }

    /// Create a group JID (g.us).
    pub fn group(id: impl Into<CompactString>) -> Self {
        Self {
            user: id.into(),
            server: Server::Group,
            ..Default::default()
        }
    }

    /// Create a newsletter (channel) JID (newsletter server).
    pub fn newsletter(id: impl Into<CompactString>) -> Self {
        Self {
            user: id.into(),
            server: Server::Newsletter,
            ..Default::default()
        }
    }

    /// Create a phone number JID with device ID
    pub fn pn_device(user: impl Into<CompactString>, device: u16) -> Self {
        Self {
            user: user.into(),
            server: Server::Pn,
            device,
            ..Default::default()
        }
    }

    /// Create a LID JID with device ID
    pub fn lid_device(user: impl Into<CompactString>, device: u16) -> Self {
        Self {
            user: user.into(),
            server: Server::Lid,
            device,
            ..Default::default()
        }
    }

    /// Returns true if this is a Phone Number based JID (s.whatsapp.net)
    #[inline]
    pub fn is_pn(&self) -> bool {
        self.server == Server::Pn
    }

    /// Returns true if this is a LID based JID
    #[inline]
    pub fn is_lid(&self) -> bool {
        self.server == Server::Lid
    }

    /// Returns the user part without the device ID suffix (e.g., "123:4" -> "123")
    #[inline]
    pub fn user_base(&self) -> &str {
        if let Some((base, _)) = self.user.split_once(':') {
            base
        } else {
            &self.user
        }
    }

    /// Helper to construct a specific device JID from this one
    pub fn with_device(&self, device_id: u16) -> Self {
        Self {
            user: self.user.clone(),
            server: self.server,
            agent: self.agent,
            device: device_id,
            integrator: self.integrator,
        }
    }

    pub fn to_non_ad(&self) -> Self {
        Self {
            user: self.user.clone(),
            server: self.server,
            integrator: self.integrator,
            ..Default::default()
        }
    }

    /// Check if this JID matches the user or their LID.
    /// Useful for checking if a participant is "us" in group messages.
    #[inline]
    pub fn matches_user_or_lid(&self, user: &Jid, lid: Option<&Jid>) -> bool {
        self.is_same_user_as(user) || lid.is_some_and(|l| self.is_same_user_as(l))
    }

    /// Normalize the JID for use in pre-key bundle storage and lookup.
    ///
    /// WhatsApp servers may return JIDs with varied agent fields, or we might derive them
    /// with agent fields in some contexts. However, pre-key bundles are stored and looked up
    /// using a normalized key where the agent is 0 for standard servers (s.whatsapp.net, lid).
    pub fn normalize_for_prekey_bundle(&self) -> Self {
        let mut jid = self.clone();
        if matches!(jid.server, Server::Pn | Server::Lid) {
            jid.agent = 0;
        }
        jid
    }

    pub fn to_ad_string(&self) -> String {
        if self.user.is_empty() {
            return self.server.as_str().to_string();
        }
        let mut s = String::with_capacity(self.user.len() + 20);
        s.push_str(&self.user);
        s.push('.');
        s.push_str(itoa::Buffer::new().format(self.agent));
        s.push(':');
        s.push_str(itoa::Buffer::new().format(self.device));
        s.push('@');
        s.push_str(self.server.as_str());
        s
    }

    /// Append the Display representation to `buf` using direct push operations,
    /// bypassing `fmt::Display` and `dyn Write` dispatch.
    #[inline]
    pub fn push_to(&self, buf: &mut String) {
        push_jid_to_string(&self.user, self.server, self.agent, self.device, buf);
    }

    /// Compare device identity (user, server, device) without allocation.
    #[inline]
    pub fn device_eq(&self, other: &Jid) -> bool {
        self.user == other.user && self.server == other.server && self.device == other.device
    }

    /// Get a borrowing key for O(1) HashSet lookups by device identity.
    #[inline]
    pub fn device_key(&self) -> DeviceKey<'_> {
        DeviceKey {
            user: &self.user,
            server: self.server,
            device: self.device,
        }
    }
}

/// Borrowing key for device identity (user, server, device). Use with HashSet for O(1) lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceKey<'a> {
    pub user: &'a str,
    pub server: Server,
    pub device: u16,
}

impl<'a> JidExt for JidRef<'a> {
    fn user(&self) -> &str {
        &self.user
    }
    fn server(&self) -> Server {
        self.server
    }
    fn device(&self) -> u16 {
        self.device
    }
    fn integrator(&self) -> u16 {
        self.integrator
    }
}

impl<'a> JidRef<'a> {
    pub fn to_owned(&self) -> Jid {
        Jid {
            user: self.user.to_compact_string(),
            server: self.server,
            agent: self.agent,
            device: self.device,
            integrator: self.integrator,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for JidRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Jid", 5)?;
        s.serialize_field("user", &*self.user)?;
        s.serialize_field("server", &self.server)?;
        s.serialize_field("agent", &self.agent)?;
        s.serialize_field("device", &self.device)?;
        s.serialize_field("integrator", &self.integrator)?;
        s.end()
    }
}

impl FromStr for Jid {
    type Err = JidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try fast path first for well-formed JIDs
        if let Some(parts) = parse_jid_fast(s) {
            return Ok(Jid {
                user: CompactString::from(parts.user),
                server: Server::try_from(parts.server)?,
                agent: parts.agent,
                device: parts.device,
                integrator: parts.integrator,
            });
        }

        // Fallback to original parsing for edge cases and validation
        // Keep server as &str to avoid allocation until we need it
        let (user_part, server) = match s.split_once('@') {
            Some((u, s)) => (u, s),
            None => ("", s),
        };

        if user_part.is_empty() && Server::try_from(server).is_err() {
            return Err(JidError::InvalidFormat(format!(
                "unknown server '{server}'"
            )));
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
                user: CompactString::from(user),
                server: Server::try_from(server)?,
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
            if num_val > u8::MAX as u16 {
                return Err(JidError::InvalidFormat(format!(
                    "Agent component out of range: {num_val}"
                )));
            }
            user = u;
            agent = num_val as u8;
        }

        Ok(Jid {
            user: CompactString::from(user),
            server: Server::try_from(server)?,
            agent,
            device,
            integrator: 0,
        })
    }
}

/// Core JID formatting logic used by `fmt::Display`, `push_jid_to_string`, and
/// `push_jid_to_compact`. Writes `{user}[.{agent}][:{device}]@{server}`.
///
/// Two flavors via `$append`:
/// - **fallible** (`f.write_str(s)?`): for `fmt::Formatter` which returns `fmt::Result`
/// - **infallible** (`$buf.push_str(s)`): for `String`/`CompactString`
macro_rules! write_jid {
    // Infallible variant: push_str/push into a growable buffer
    (infallible $buf:expr, $user:expr, $server:expr, $agent:expr, $device:expr) => {{
        let (user, server, agent, device) = ($user, $server, $agent, $device);
        if user.is_empty() {
            $buf.push_str(server.as_str());
            return;
        }
        $buf.push_str(user);
        if agent > 0
            && !matches!(
                server,
                Server::Pn | Server::Lid | Server::Hosted | Server::HostedLid
            )
        {
            $buf.push('.');
            $buf.push_str(itoa::Buffer::new().format(agent));
        }
        if device > 0 {
            $buf.push(':');
            $buf.push_str(itoa::Buffer::new().format(device));
        }
        $buf.push('@');
        $buf.push_str(server.as_str());
    }};
    // Fallible variant: write_str into fmt::Formatter
    (fallible $f:expr, $user:expr, $server:expr, $agent:expr, $device:expr) => {{
        let (user, server, agent, device) = ($user, $server, $agent, $device);
        if user.is_empty() {
            return $f.write_str(server.as_str());
        }
        $f.write_str(user)?;
        if agent > 0
            && !matches!(
                server,
                Server::Pn | Server::Lid | Server::Hosted | Server::HostedLid
            )
        {
            $f.write_str(".")?;
            $f.write_str(itoa::Buffer::new().format(agent))?;
        }
        if device > 0 {
            $f.write_str(":")?;
            $f.write_str(itoa::Buffer::new().format(device))?;
        }
        $f.write_str("@")?;
        $f.write_str(server.as_str())
    }};
}

/// Write the JID display representation directly into a `String`,
/// bypassing `fmt::Display` and `dyn Write` dispatch entirely.
#[inline]
pub fn push_jid_to_string(user: &str, server: Server, agent: u8, device: u16, buf: &mut String) {
    write_jid!(infallible buf, user, server, agent, device);
}

/// Write the JID display representation directly into a `CompactString`,
/// bypassing `fmt::Display` and `dyn Write` dispatch entirely.
#[inline]
pub fn push_jid_to_compact(
    user: &str,
    server: Server,
    agent: u8,
    device: u16,
    buf: &mut CompactString,
) {
    write_jid!(infallible buf, user, server, agent, device);
}

impl fmt::Display for Jid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_jid!(fallible f, &*self.user, self.server, self.agent, self.device)
    }
}

impl<'a> fmt::Display for JidRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_jid!(fallible f, &*self.user, self.server, self.agent, self.device)
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
        assert_jid_parse_and_display(
            input,
            expected_user,
            expected_server,
            expected_device,
            expected_agent,
            input,
        );
    }

    /// Helper function to test parsing and display with a custom expected output.
    fn assert_jid_parse_and_display(
        input: &str,
        expected_user: &str,
        expected_server: &str,
        expected_device: u16,
        expected_agent: u8,
        expected_output: &str,
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
            formatted, expected_output,
            "Formatted string did not match expected output for {}",
            input
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

        // Server-only JID: parsing "s.whatsapp.net" should display as "s.whatsapp.net" (no @ prefix)
        // This matches WhatsApp Web behavior where server-only JIDs don't have @ prefix
        assert_jid_roundtrip("s.whatsapp.net", "", "s.whatsapp.net", 0, 0);

        // LID JID cases (critical for the bug)
        assert_jid_roundtrip("12345.6789@lid", "12345.6789", "lid", 0, 0);
        assert_jid_roundtrip("12345.6789:25@lid", "12345.6789", "lid", 25, 0);
    }

    #[test]
    fn test_special_from_str_parsing() {
        // Test parsing of JIDs with an agent, which should be stored in the struct
        let jid = Jid::from_str("1234567890.2:15@hosted").expect("test hosted JID should be valid");
        assert_eq!(jid.user, "1234567890");
        assert_eq!(jid.server, "hosted");
        assert_eq!(jid.device, 15);
        assert_eq!(jid.agent, 2);
    }

    #[test]
    fn test_manual_jid_formatting_edge_cases() {
        // This test directly validates the fixes for the parity failures.
        // We manually construct the Jid struct as the binary decoder would,
        // then we assert that its string representation is correct.

        // Failure Case 1: An AD-JID for s.whatsapp.net decoded with an agent.
        // The Display trait MUST NOT show the agent number.
        let jid1 = Jid {
            user: "1234567890".into(),
            server: Server::Pn,
            device: 15,
            agent: 2,
            integrator: 0,
        };
        assert_eq!(jid1.to_string(), "1234567890:15@s.whatsapp.net");

        let jid2 = Jid {
            user: "12345.6789".into(),
            server: Server::Lid,
            device: 25,
            agent: 1,
            integrator: 0,
        };
        assert_eq!(jid2.to_string(), "12345.6789:25@lid");

        let jid3 = Jid {
            user: "1234567890".into(),
            server: Server::Hosted,
            device: 15,
            agent: 2,
            integrator: 0,
        };
        assert_eq!(jid3.to_string(), "1234567890:15@hosted");

        // Agent SHOULD be displayed for non-AD servers (e.g., bot, interop)
        let jid4 = Jid {
            user: "user".into(),
            server: Server::Bot,
            device: 10,
            agent: 5,
            integrator: 0,
        };
        assert_eq!(jid4.to_string(), "user.5:10@bot");
    }

    #[test]
    fn test_invalid_jids_should_fail_to_parse() {
        assert!(Jid::from_str("thisisnotajid").is_err());
        assert!(Jid::from_str("").is_err());
        // "@s.whatsapp.net" is now valid - it's the protocol format for server-only JIDs
        assert!(Jid::from_str("@s.whatsapp.net").is_ok());
        // But "@unknown.server" should still fail
        assert!(Jid::from_str("@unknown.server").is_err());
        // Jid::from_str("2") should not be possible due to type constraints,
        // but if it were, it should fail. The string must contain '@'.
        assert!(Jid::from_str("2").is_err());
    }

    /// Tests for HOSTED device detection (`is_hosted()` method).
    ///
    /// # Context: What are HOSTED devices?
    ///
    /// HOSTED devices (also known as Cloud API or Meta Business API devices) are
    /// WhatsApp Business accounts that use Meta's server-side infrastructure instead
    /// of traditional end-to-end encryption with Signal protocol.
    ///
    /// ## Key characteristics:
    /// - Device ID is always 99 (`:99`)
    /// - Server is `@hosted` (phone-based) or `@hosted.lid` (LID-based)
    /// - They do NOT use Signal protocol prekeys
    /// - They should be EXCLUDED from group message fanout
    /// - They CAN receive 1:1 messages (but prekey fetch will fail, causing graceful skip)
    ///
    /// ## Why exclude from groups?
    /// WhatsApp Web explicitly filters hosted devices from group SKDM (Sender Key
    /// Distribution Message) distribution. From WhatsApp Web JS (`getFanOutList`):
    /// ```javascript
    /// var isHosted = e.id === 99 || e.isHosted === true;
    /// var includeInFanout = !isHosted || isOneToOneChat;
    /// ```
    ///
    /// ## JID formats:
    /// - Phone-based: `5511999887766:99@hosted`
    /// - LID-based: `100000012345678:99@hosted.lid`
    /// - Regular device with ID 99: `5511999887766:99@s.whatsapp.net` (also hosted!)
    #[test]
    fn test_is_hosted_device_detection() {
        // === HOSTED DEVICES (should return true) ===

        // Case 1: Device ID 99 on regular server (Cloud API business account)
        // This is the most common case - a business using Meta's Cloud API
        let cloud_api_device: Jid = "5511999887766:99@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        assert!(
            cloud_api_device.is_hosted(),
            "Device ID 99 on s.whatsapp.net should be detected as hosted (Cloud API)"
        );

        // Case 2: Device ID 99 on LID server
        let cloud_api_lid: Jid = "100000012345678:99@lid"
            .parse()
            .expect("test JID should be valid");
        assert!(
            cloud_api_lid.is_hosted(),
            "Device ID 99 on lid server should be detected as hosted"
        );

        // Case 3: Explicit @hosted server (phone-based hosted JID)
        let hosted_server: Jid = "5511999887766:99@hosted"
            .parse()
            .expect("test JID should be valid");
        assert!(
            hosted_server.is_hosted(),
            "JID with @hosted server should be detected as hosted"
        );

        // Case 4: Explicit @hosted.lid server (LID-based hosted JID)
        let hosted_lid_server: Jid = "100000012345678:99@hosted.lid"
            .parse()
            .expect("test JID should be valid");
        assert!(
            hosted_lid_server.is_hosted(),
            "JID with @hosted.lid server should be detected as hosted"
        );

        // Case 5: @hosted server with different device ID (edge case)
        // Even with device ID != 99, if server is @hosted, it's a hosted device
        let hosted_server_other_device: Jid = "5511999887766:0@hosted"
            .parse()
            .expect("test JID should be valid");
        assert!(
            hosted_server_other_device.is_hosted(),
            "JID with @hosted server should be hosted regardless of device ID"
        );

        // === NON-HOSTED DEVICES (should return false) ===

        // Case 6: Regular phone device (primary phone, device 0)
        let regular_phone: Jid = "5511999887766:0@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        assert!(
            !regular_phone.is_hosted(),
            "Regular phone device (ID 0) should NOT be hosted"
        );

        // Case 7: Companion device (WhatsApp Web, device 33+)
        let companion_device: Jid = "5511999887766:33@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        assert!(
            !companion_device.is_hosted(),
            "Companion device (ID 33) should NOT be hosted"
        );

        // Case 8: Regular LID device
        let regular_lid: Jid = "100000012345678:0@lid"
            .parse()
            .expect("test JID should be valid");
        assert!(
            !regular_lid.is_hosted(),
            "Regular LID device should NOT be hosted"
        );

        // Case 9: LID companion device
        let lid_companion: Jid = "100000012345678:33@lid"
            .parse()
            .expect("test JID should be valid");
        assert!(
            !lid_companion.is_hosted(),
            "LID companion device (ID 33) should NOT be hosted"
        );

        // Case 10: Group JID (not a device at all)
        let group_jid: Jid = "120363012345678@g.us"
            .parse()
            .expect("test JID should be valid");
        assert!(
            !group_jid.is_hosted(),
            "Group JID should NOT be detected as hosted"
        );

        // Case 11: User JID without device
        let user_jid: Jid = "5511999887766@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        assert!(
            !user_jid.is_hosted(),
            "User JID without device should NOT be hosted"
        );

        // Case 12: Bot device
        let bot_jid: Jid = "13136555001:0@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        assert!(
            !bot_jid.is_hosted(),
            "Bot JID should NOT be detected as hosted (different mechanism)"
        );
    }

    /// Tests that document the filtering behavior for group messages.
    ///
    /// # Why this matters:
    /// When sending a group message, we distribute Sender Key Distribution Messages
    /// (SKDM) to all participant devices. However, HOSTED devices:
    /// 1. Don't use Signal protocol, so they can't process SKDM
    /// 2. WhatsApp Web explicitly excludes them from group fanout
    /// 3. Including them would cause unnecessary prekey fetch failures
    ///
    /// This test documents the expected behavior when filtering device lists.
    #[test]
    fn test_hosted_device_filtering_for_groups() {
        // Simulate a group with mixed device types
        let devices: Vec<Jid> = vec![
            // Regular devices that SHOULD receive SKDM
            "5511999887766:0@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"), // Phone
            "5511999887766:33@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"), // WhatsApp Web
            "5521988776655:0@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"), // Another user's phone
            "100000012345678:0@lid"
                .parse()
                .expect("test JID should be valid"), // LID device
            "100000012345678:33@lid"
                .parse()
                .expect("test JID should be valid"), // LID companion
            // HOSTED devices that should be EXCLUDED from group SKDM
            "5531977665544:99@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"), // Cloud API business
            "100000087654321:99@lid"
                .parse()
                .expect("test JID should be valid"), // Cloud API on LID
            "5541966554433:99@hosted"
                .parse()
                .expect("test JID should be valid"), // Explicit hosted
        ];

        // Filter out hosted devices (this is what prepare_group_stanza does)
        let filtered: Vec<&Jid> = devices.iter().filter(|jid| !jid.is_hosted()).collect();

        // Verify correct filtering
        assert_eq!(
            filtered.len(),
            5,
            "Should have 5 non-hosted devices after filtering"
        );

        // All filtered devices should NOT be hosted
        for jid in &filtered {
            assert!(
                !jid.is_hosted(),
                "Filtered list should not contain hosted devices: {}",
                jid
            );
        }

        // Count how many hosted devices were filtered out
        let hosted_count = devices.iter().filter(|jid| jid.is_hosted()).count();
        assert_eq!(hosted_count, 3, "Should have filtered out 3 hosted devices");
    }

    #[test]
    fn test_jid_pn_factory() {
        let jid = Jid::pn("1234567890");
        assert_eq!(jid.user, "1234567890");
        assert_eq!(jid.server, DEFAULT_USER_SERVER);
        assert_eq!(jid.device, 0);
        assert!(jid.is_pn());
    }

    #[test]
    fn test_jid_lid_factory() {
        let jid = Jid::lid("100000012345678");
        assert_eq!(jid.user, "100000012345678");
        assert_eq!(jid.server, HIDDEN_USER_SERVER);
        assert_eq!(jid.device, 0);
        assert!(jid.is_lid());
    }

    #[test]
    fn test_jid_group_factory() {
        let jid = Jid::group("123456789-1234567890");
        assert_eq!(jid.user, "123456789-1234567890");
        assert_eq!(jid.server, GROUP_SERVER);
        assert!(jid.is_group());
    }

    #[test]
    fn test_jid_pn_device_factory() {
        let jid = Jid::pn_device("1234567890", 5);
        assert_eq!(jid.user, "1234567890");
        assert_eq!(jid.server, DEFAULT_USER_SERVER);
        assert_eq!(jid.device, 5);
        assert!(jid.is_pn());
        assert!(jid.is_ad());
    }

    #[test]
    fn test_jid_lid_device_factory() {
        let jid = Jid::lid_device("100000012345678", 33);
        assert_eq!(jid.user, "100000012345678");
        assert_eq!(jid.server, HIDDEN_USER_SERVER);
        assert_eq!(jid.device, 33);
        assert!(jid.is_lid());
        assert!(jid.is_ad());
    }

    #[test]
    fn test_status_broadcast_jid() {
        let jid = Jid::status_broadcast();
        assert_eq!(jid.user, STATUS_BROADCAST_USER);
        assert_eq!(jid.server, BROADCAST_SERVER);
        assert_eq!(jid.device, 0);
        assert!(jid.is_status_broadcast());
        assert!(!jid.is_group());
        assert!(!jid.is_broadcast_list());
        assert_eq!(jid.to_string(), "status@broadcast");

        // Parsing round-trip
        let parsed: Jid = "status@broadcast".parse().expect("should parse");
        assert!(parsed.is_status_broadcast());
        assert_eq!(parsed.user, "status");
        assert_eq!(parsed.server, "broadcast");

        // Regular broadcast list should NOT be status broadcast
        let broadcast_list = Jid::new("12345", Server::Broadcast);
        assert!(broadcast_list.is_broadcast_list());
        assert!(!broadcast_list.is_status_broadcast());
    }

    #[test]
    fn test_jid_to_non_ad_preserves_user_server() {
        // Verify to_non_ad strips device but keeps user/server
        let device_jid = Jid::pn_device("1234567890", 33);
        let non_ad = device_jid.to_non_ad();
        assert_eq!(non_ad.user, "1234567890");
        assert_eq!(non_ad.server, DEFAULT_USER_SERVER);
        assert_eq!(non_ad.device, 0);
        assert!(!non_ad.is_ad());

        // LID variant
        let lid_device = Jid::lid_device("100000012345678", 25);
        let lid_non_ad = lid_device.to_non_ad();
        assert_eq!(lid_non_ad.user, "100000012345678");
        assert_eq!(lid_non_ad.server, HIDDEN_USER_SERVER);
        assert_eq!(lid_non_ad.device, 0);

        // status@broadcast stays the same
        let status = Jid::status_broadcast();
        let status_non_ad = status.to_non_ad();
        assert_eq!(status_non_ad.to_string(), "status@broadcast");
    }

    #[test]
    fn test_jid_factories_with_string_types() {
        // Test with &str
        let jid1 = Jid::pn("123");
        assert_eq!(jid1.user, "123");

        // Test with String
        let jid2 = Jid::lid(String::from("456"));
        assert_eq!(jid2.user, "456");

        // Test with owned String
        let user = "789".to_string();
        let jid3 = Jid::group(user);
        assert_eq!(jid3.user, "789");
    }

    /// Verify that all JID formatting paths produce identical output:
    /// `Jid::Display`, `JidRef::Display`, `push_jid_to_string`, `push_jid_to_compact`,
    /// and `Jid::push_to`. Exercises the agent-elision rules across server variants.
    #[test]
    fn test_jid_format_parity() {
        struct Case {
            user: &'static str,
            server: Server,
            agent: u8,
            device: u16,
        }

        let cases = [
            // Empty user (server-only JID)
            Case {
                user: "",
                server: Server::Pn,
                agent: 0,
                device: 0,
            },
            // Basic phone, no agent/device
            Case {
                user: "5511999887766",
                server: Server::Pn,
                agent: 0,
                device: 0,
            },
            // Phone with device
            Case {
                user: "5511999887766",
                server: Server::Pn,
                agent: 0,
                device: 2,
            },
            // Phone with agent (suppressed for Pn)
            Case {
                user: "5511999887766",
                server: Server::Pn,
                agent: 3,
                device: 15,
            },
            // LID with agent (suppressed for Lid)
            Case {
                user: "12345.6789",
                server: Server::Lid,
                agent: 1,
                device: 25,
            },
            // Hosted with agent (suppressed)
            Case {
                user: "100000012345678",
                server: Server::Hosted,
                agent: 2,
                device: 99,
            },
            // HostedLid with agent (suppressed)
            Case {
                user: "100000012345678",
                server: Server::HostedLid,
                agent: 1,
                device: 99,
            },
            // Group (no agent, no device)
            Case {
                user: "120363012345678901",
                server: Server::Group,
                agent: 0,
                device: 0,
            },
            // Bot with agent (shown)
            Case {
                user: "user",
                server: Server::Bot,
                agent: 5,
                device: 10,
            },
            // Interop with agent (shown)
            Case {
                user: "447911123456",
                server: Server::Interop,
                agent: 3,
                device: 0,
            },
            // Messenger with device, no agent
            Case {
                user: "messenger_user",
                server: Server::Messenger,
                agent: 0,
                device: 50,
            },
            // Broadcast
            Case {
                user: "status",
                server: Server::Broadcast,
                agent: 0,
                device: 0,
            },
            // Newsletter
            Case {
                user: "newsletter_id",
                server: Server::Newsletter,
                agent: 0,
                device: 0,
            },
            // Max values
            Case {
                user: "447911123456789",
                server: Server::Pn,
                agent: 255,
                device: 65535,
            },
            // Short user
            Case {
                user: "1",
                server: Server::Legacy,
                agent: 0,
                device: 1,
            },
        ];

        for (i, c) in cases.iter().enumerate() {
            let jid = Jid {
                user: c.user.into(),
                server: c.server,
                agent: c.agent,
                device: c.device,
                integrator: 0,
            };

            // Reference: Display impl (via write_jid! fallible)
            let display = jid.to_string();

            // JidRef Display
            let jid_ref = JidRef {
                user: NodeStr::Borrowed(c.user),
                server: c.server,
                agent: c.agent,
                device: c.device,
                integrator: 0,
            };
            let ref_display = jid_ref.to_string();

            // push_jid_to_string
            let mut string_buf = String::new();
            push_jid_to_string(c.user, c.server, c.agent, c.device, &mut string_buf);

            // push_jid_to_compact
            let mut compact_buf = CompactString::default();
            push_jid_to_compact(c.user, c.server, c.agent, c.device, &mut compact_buf);

            // Jid::push_to
            let mut push_buf = String::new();
            jid.push_to(&mut push_buf);

            assert_eq!(display, ref_display, "case {i}: Display vs JidRef::Display");
            assert_eq!(
                display, string_buf,
                "case {i}: Display vs push_jid_to_string"
            );
            assert_eq!(
                display,
                compact_buf.as_str(),
                "case {i}: Display vs push_jid_to_compact"
            );
            assert_eq!(display, push_buf, "case {i}: Display vs Jid::push_to");
        }
    }
}
