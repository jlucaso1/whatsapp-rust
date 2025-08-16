use wacore::appstate::patch_decode::WAPatchName;
use waproto::whatsapp::message::HistorySyncNotification;

#[derive(Debug)]
pub enum MajorSyncTask {
    HistorySync {
        message_id: String,
        notification: Box<HistorySyncNotification>,
    },
    AppStateSync {
        name: WAPatchName,
        full_sync: bool,
    },
}
