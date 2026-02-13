//! Contact information feature.
//!
//! Profile picture types are defined in `wacore::iq::contacts`.
//! Usync types are defined in `wacore::iq::usync`.

use crate::client::Client;
use anyhow::Result;
use log::debug;
use std::collections::HashMap;
use wacore::iq::contacts::{ProfilePictureSpec, ProfilePictureType};
use wacore::iq::usync::{ContactInfoSpec, IsOnWhatsAppSpec, UserInfoSpec};
use wacore_binary::jid::{Jid, JidExt};

// Re-export types from wacore
pub use wacore::iq::contacts::ProfilePicture;
pub use wacore::iq::usync::{ContactInfo, IsOnWhatsAppResult, UserInfo};

pub struct Contacts<'a> {
    client: &'a Client,
}

impl<'a> Contacts<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn is_on_whatsapp(&self, phones: &[&str]) -> Result<Vec<IsOnWhatsAppResult>> {
        if phones.is_empty() {
            return Ok(Vec::new());
        }

        debug!("is_on_whatsapp: checking {} numbers", phones.len());

        let request_id = self.client.generate_request_id();
        let phone_strings: Vec<String> = phones.iter().map(|s| s.to_string()).collect();
        let spec = IsOnWhatsAppSpec::new(phone_strings, request_id);

        Ok(self.client.execute(spec).await?)
    }

    pub async fn get_info(&self, phones: &[&str]) -> Result<Vec<ContactInfo>> {
        if phones.is_empty() {
            return Ok(Vec::new());
        }

        debug!("get_info: fetching info for {} numbers", phones.len());

        let request_id = self.client.generate_request_id();
        let phone_strings: Vec<String> = phones.iter().map(|s| s.to_string()).collect();
        let spec = ContactInfoSpec::new(phone_strings, request_id);

        Ok(self.client.execute(spec).await?)
    }

    pub async fn get_profile_picture(
        &self,
        jid: &Jid,
        preview: bool,
    ) -> Result<Option<ProfilePicture>> {
        debug!(
            "get_profile_picture: fetching {} picture for {}",
            if preview { "preview" } else { "full" },
            jid
        );

        let picture_type = if preview {
            ProfilePictureType::Preview
        } else {
            ProfilePictureType::Full
        };
        let mut spec = ProfilePictureSpec::new(jid, picture_type);

        // Include tctoken for user JIDs (skip groups, newsletters)
        if !jid.is_group()
            && !jid.is_newsletter()
            && let Some(token) = self.client.lookup_tc_token_for_jid(jid).await
        {
            spec = spec.with_tc_token(token);
        }

        Ok(self.client.execute(spec).await?)
    }

    pub async fn get_user_info(&self, jids: &[Jid]) -> Result<HashMap<Jid, UserInfo>> {
        if jids.is_empty() {
            return Ok(HashMap::new());
        }

        debug!("get_user_info: fetching info for {} JIDs", jids.len());

        let request_id = self.client.generate_request_id();
        let spec = UserInfoSpec::new(jids.to_vec(), request_id);

        Ok(self.client.execute(spec).await?)
    }
}

impl Client {
    pub fn contacts(&self) -> Contacts<'_> {
        Contacts::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_info_struct() {
        let jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let lid: Jid = "12345678@lid".parse().expect("test JID should be valid");

        let info = ContactInfo {
            jid: jid.clone(),
            lid: Some(lid.clone()),
            is_registered: true,
            is_business: false,
            status: Some("Hey there!".to_string()),
            picture_id: Some(123456789),
        };

        assert!(info.is_registered);
        assert!(!info.is_business);
        assert_eq!(info.status, Some("Hey there!".to_string()));
        assert_eq!(info.picture_id, Some(123456789));
        assert!(info.lid.is_some());
    }

    #[test]
    fn test_profile_picture_struct() {
        let pic = ProfilePicture {
            id: "123456789".to_string(),
            url: "https://example.com/pic.jpg".to_string(),
            direct_path: Some("/v/pic.jpg".to_string()),
        };

        assert_eq!(pic.id, "123456789");
        assert_eq!(pic.url, "https://example.com/pic.jpg");
        assert!(pic.direct_path.is_some());
    }

    #[test]
    fn test_is_on_whatsapp_result_struct() {
        let jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let result = IsOnWhatsAppResult {
            jid,
            is_registered: true,
        };

        assert!(result.is_registered);
    }
}
