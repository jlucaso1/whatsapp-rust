//! Canonical registry of MEX (GraphQL) persisted-query descriptors.
//!
//! The numeric `id` rotates with the WA Web bundle; the `name` does not.
//! To refresh an id, grep the bundle for the `name` and copy the adjacent
//! `id: "…"` field.

use crate::iq::mex::MexDoc;

pub mod community {
    use super::MexDoc;

    pub const FETCH_ALL_SUBGROUPS: MexDoc = MexDoc {
        name: "WAWebMexFetchAllSubgroupsJobQuery",
        id: "9935467776504344",
    };

    pub const FETCH_SUBGROUP_SUGGESTIONS: MexDoc = MexDoc {
        name: "WAWebMexFetchSubgroupSuggestionsJobQuery",
        id: "23972005349071865",
    };

    pub const FETCH_SUBGROUP_PARTICIPANT_COUNT: MexDoc = MexDoc {
        name: "WAWebMexQuerySubgroupParticipantCountJobQuery",
        id: "24079399904996141",
    };
}

pub mod groups {
    use super::MexDoc;

    pub const UPDATE_GROUP_PROPERTY: MexDoc = MexDoc {
        name: "WAWebMexUpdateGroupPropertyJobMutation",
        id: "9418211574894172",
    };
}

pub mod newsletter {
    use super::MexDoc;

    pub const LIST_SUBSCRIBED: MexDoc = MexDoc {
        name: "WAWebMexListSubscribedNewslettersJobQuery",
        id: "33101596156151910",
    };

    pub const FETCH_METADATA: MexDoc = MexDoc {
        name: "WAWebMexFetchNewsletterMetadataJobQuery",
        id: "25383075034668475",
    };

    pub const FETCH_DEHYDRATED: MexDoc = MexDoc {
        name: "WAWebMexFetchNewsletterDehydratedJobQuery",
        id: "30328461880085868",
    };

    pub const CREATE: MexDoc = MexDoc {
        name: "WAWebMexCreateNewsletterJobMutation",
        id: "25149874324715067",
    };

    pub const UPDATE: MexDoc = MexDoc {
        name: "WAWebMexUpdateNewsletterJobMutation",
        id: "24250201037901610",
    };

    pub const JOIN: MexDoc = MexDoc {
        name: "WAWebMexJoinNewsletterJobMutation",
        id: "24404358912487870",
    };

    pub const LEAVE: MexDoc = MexDoc {
        name: "WAWebMexLeaveNewsletterJobMutation",
        id: "9767147403369991",
    };

    pub const FETCH_ADMIN_COUNT: MexDoc = MexDoc {
        name: "WAWebMexFetchNewsletterAdminCountJobQuery",
        id: "29186079397702825",
    };

    pub const FETCH_ADMIN_CAPABILITIES: MexDoc = MexDoc {
        name: "WAWebMexFetchNewsletterAdminCapabilitiesJobQuery",
        id: "9801384413216421",
    };

    pub const FETCH_PENDING_INVITES: MexDoc = MexDoc {
        name: "WAWebMexFetchNewsletterPendingInvitesJobQuery",
        id: "9783111038412085",
    };

    pub const FETCH_SUBSCRIBERS: MexDoc = MexDoc {
        name: "WAWebMexFetchNewsletterSubscribersJobQuery",
        id: "9537574256318798",
    };

    pub const FETCH_REACTION_SENDERS: MexDoc = MexDoc {
        name: "WAWebMexFetchNewsletterMessageReactionSenderListJobQuery",
        id: "29575462448733991",
    };
}

pub mod reachout_timelock {
    use super::MexDoc;

    pub const FETCH: MexDoc = MexDoc {
        name: "WAWebMexFetchReachoutTimelockJobQuery",
        id: "23983697327930364",
    };
}
