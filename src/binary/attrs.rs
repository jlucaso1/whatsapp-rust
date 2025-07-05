use crate::binary::error::{BinaryError, Result};
use crate::binary::node::{Attrs, Node};
use crate::types::jid::Jid;
use chrono::{DateTime, Utc};
use std::str::FromStr;

pub struct AttrParser<'a> {
    attrs: &'a Attrs,
    pub errors: Vec<BinaryError>,
}

impl<'a> AttrParser<'a> {
    pub(crate) fn new(node: &'a Node) -> Self {
        Self {
            attrs: &node.attrs,
            errors: Vec::new(),
        }
    }

    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn finish(&self) -> Result<()> {
        if self.ok() {
            Ok(())
        } else {
            Err(BinaryError::AttrList(self.errors.clone()))
        }
    }

    fn get_raw(&mut self, key: &str, require: bool) -> Option<&'a String> {
        let val = self.attrs.get(key);
        if require && val.is_none() {
            self.errors.push(BinaryError::AttrParse(format!(
                "Required attribute '{key}' not found"
            )));
        }
        val
    }

    // --- String ---
    pub fn optional_string(&mut self, key: &str) -> Option<&'a str> {
        self.get_raw(key, false).map(|s| s.as_str())
    }

    pub fn string(&mut self, key: &str) -> String {
        self.get_raw(key, true).cloned()
            .unwrap_or_default()
    }

    // --- JID ---
    pub fn optional_jid(&mut self, key: &str) -> Option<Jid> {
        self.get_raw(key, false)
            .and_then(|s| match Jid::from_str(s) {
                Ok(jid) => Some(jid),
                Err(e) => {
                    self.errors.push(BinaryError::from(e));
                    None
                }
            })
    }

    pub fn jid(&mut self, key: &str) -> Jid {
        self.get_raw(key, true); // Push "not found" error if needed.
        self.optional_jid(key).unwrap_or_default()
    }

    // --- Boolean ---
    fn get_bool(&mut self, key: &str, require: bool) -> Option<bool> {
        self.get_raw(key, require)
            .and_then(|s| match s.parse::<bool>() {
                Ok(val) => Some(val),
                Err(e) => {
                    self.errors.push(BinaryError::AttrParse(format!(
                        "Failed to parse bool from '{s}' for key '{key}': {e}"
                    )));
                    None
                }
            })
    }

    pub fn optional_bool(&mut self, key: &str) -> bool {
        self.get_bool(key, false).unwrap_or(false)
    }

    pub fn bool(&mut self, key: &str) -> bool {
        self.get_bool(key, true).unwrap_or(false)
    }

    // --- u64 ---
    pub fn optional_u64(&mut self, key: &str) -> Option<u64> {
        self.get_raw(key, false)
            .and_then(|s| match s.parse::<u64>() {
                Ok(val) => Some(val),
                Err(e) => {
                    self.errors.push(BinaryError::AttrParse(format!(
                        "Failed to parse u64 from '{s}' for key '{key}': {e}"
                    )));
                    None
                }
            })
    }

    pub fn unix_time(&mut self, key: &str) -> DateTime<Utc> {
        self.get_raw(key, true);
        self.optional_unix_time(key).unwrap_or_default()
    }
    pub fn optional_unix_time(&mut self, key: &str) -> Option<DateTime<Utc>> {
        self.get_i64(key, false).and_then(|ts| {
            if ts == 0 {
                None
            } else {
                DateTime::from_timestamp(ts, 0)
            }
        })
    }
    pub fn unix_milli(&mut self, key: &str) -> DateTime<Utc> {
        self.get_raw(key, true);
        self.optional_unix_milli(key).unwrap_or_default()
    }
    pub fn optional_unix_milli(&mut self, key: &str) -> Option<DateTime<Utc>> {
        self.get_i64(key, false).and_then(|ms| {
            if ms == 0 {
                None
            } else {
                DateTime::from_timestamp_millis(ms)
            }
        })
    }
    fn get_i64(&mut self, key: &str, require: bool) -> Option<i64> {
        self.get_raw(key, require)
            .and_then(|s| match s.parse::<i64>() {
                Ok(val) => Some(val),
                Err(e) => {
                    self.errors.push(BinaryError::AttrParse(format!(
                        "Failed to parse i64 from '{s}' for key '{key}': {e}"
                    )));
                    None
                }
            })
    }
}
