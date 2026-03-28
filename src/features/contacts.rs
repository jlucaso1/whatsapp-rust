//! Contact information feature.
//!
//! Profile picture types are defined in `wacore::iq::contacts`.
//! Usync types are defined in `wacore::iq::usync`.

use crate::client::Client;
use crate::request::IqError;
use anyhow::Result;
use log::debug;
use std::collections::HashMap;
use wacore::iq::contacts::{ProfilePictureSpec, ProfilePictureType};
use wacore::iq::usync::{IsOnWhatsAppSpec, IsOnWhatsAppUser, UserInfoSpec};
use wacore_binary::jid::{Jid, JidExt};

// Re-export types from wacore
pub use wacore::iq::contacts::ProfilePicture;
pub use wacore::iq::usync::{IsOnWhatsAppResult, UserInfo};

pub struct Contacts<'a> {
    client: &'a Client,
}

impl<'a> Contacts<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    async fn persist_lid_mappings<'b, I>(&self, entries: I)
    where
        I: IntoIterator<Item = (&'b Jid, Option<&'b Jid>)>,
    {
        for (jid, lid) in entries {
            let Some(lid) = lid else {
                continue;
            };
            if !jid.is_pn() || !lid.is_lid() {
                continue;
            }
            if let Err(err) = self
                .client
                .add_lid_pn_mapping(
                    &lid.user,
                    &jid.user,
                    crate::lid_pn_cache::LearningSource::Usync,
                )
                .await
            {
                log::warn!(
                    "Failed to persist usync LID mapping {} -> {}: {err}",
                    jid,
                    lid
                );
            }
        }
    }

    /// Check if JIDs are registered on WhatsApp.
    ///
    /// Accepts both PN JIDs (`Jid::pn("1234567890")`) and LID JIDs (`Jid::lid("100000001")`).
    pub async fn is_on_whatsapp(&self, jids: &[Jid]) -> Result<Vec<IsOnWhatsAppResult>> {
        if jids.is_empty() {
            return Ok(Vec::new());
        }

        debug!("is_on_whatsapp: checking {} JIDs", jids.len());

        let mut users = Vec::with_capacity(jids.len());
        for jid in jids {
            let known_lid = if jid.is_pn() {
                self.client.lid_pn_cache.get_current_lid(&jid.user).await
            } else {
                None
            };
            users.push(IsOnWhatsAppUser {
                jid: jid.to_non_ad(),
                known_lid,
            });
        }

        let request_id = self.client.generate_request_id();
        let spec = IsOnWhatsAppSpec::new(users, request_id);
        let results = self.client.execute(spec).await?;

        self.persist_lid_mappings(results.iter().map(|r| (&r.jid, r.lid.as_ref())))
            .await;
        self.persist_lid_mappings(results.iter().filter_map(|r| {
            if r.jid.is_lid() {
                r.pn_jid.as_ref().map(|pn| (pn, Some(&r.jid)))
            } else {
                None
            }
        }))
        .await;

        Ok(results)
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

        match self.client.execute(spec).await {
            Ok(pic) => Ok(pic),
            // 404/401 = no profile picture (or not authorized to see it).
            // WhatsApp server returns type="error" IQ for these cases.
            Err(IqError::ServerError { code, .. }) if code == 404 || code == 401 => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn get_user_info(&self, jids: &[Jid]) -> Result<HashMap<Jid, UserInfo>> {
        if jids.is_empty() {
            return Ok(HashMap::new());
        }

        debug!("get_user_info: fetching info for {} JIDs", jids.len());

        let request_id = self.client.generate_request_id();
        let spec = UserInfoSpec::new(jids.to_vec(), request_id);

        let info = self.client.execute(spec).await?;
        self.persist_lid_mappings(info.values().map(|entry| (&entry.jid, entry.lid.as_ref())))
            .await;
        Ok(info)
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
    fn test_is_on_whatsapp_result_struct() {
        let jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let result = IsOnWhatsAppResult {
            jid,
            lid: Some(Jid::lid("100000001")),
            pn_jid: None,
            is_registered: true,
            is_business: false,
        };

        assert!(result.is_registered);
        assert!(!result.is_business);
        assert!(result.lid.is_some());
    }

    #[test]
    fn test_profile_picture_struct() {
        let pic = ProfilePicture {
            id: "123456789".to_string(),
            url: "https://example.com/pic.jpg".to_string(),
            direct_path: Some("/v/pic.jpg".to_string()),
            hash: None,
        };

        assert_eq!(pic.id, "123456789");
        assert_eq!(pic.url, "https://example.com/pic.jpg");
        assert!(pic.direct_path.is_some());
    }
}
