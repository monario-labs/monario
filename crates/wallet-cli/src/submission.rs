//! Publish only authenticated, durably stored signed bytes to a pinned local inbox.
use super::*;
use monario_node::submission::Inbox;
#[path = "rebroadcast.rs"]
pub(super) mod rebroadcast;
#[derive(Clone)]
pub(super) struct Destination {
    directory: PathBuf,
    inbox: String,
    node_key: [u8; 32],
}
impl Destination {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        let directory = PathBuf::from(options.remove("--node-directory").ok_or(Error::Arguments)?);
        if directory.as_os_str().is_empty() {
            return Err(Error::Arguments);
        }
        Ok(Self {
            directory,
            inbox: name(&text(options.remove("--submission-inbox"))?)?,
            node_key: balance::hash(&text(options.remove("--node-public-key"))?)?,
        })
    }
    pub(super) fn check(&self, profile: [u8; 32]) -> Result<(), Error> {
        let inbox = Inbox::open(&self.directory, &self.inbox, profile, self.node_key)
            .map_err(|_| Error::Submission)?;
        if inbox.lifecycle().map_err(|_| Error::Submission)?.phase != 0 {
            return Err(Error::Submission);
        }
        Ok(())
    }
    pub(super) fn publish(
        self,
        store: &WalletStore,
        profile: [u8; 32],
        reservation: [u8; 16],
    ) -> Result<serde_json::Value, Error> {
        execute(
            store,
            true,
            Options {
                destination: self,
                profile,
                reservation,
            },
        )
    }
}
pub(super) struct Options {
    destination: Destination,
    profile: [u8; 32],
    reservation: [u8; 16],
}
impl Options {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        Ok(Self {
            destination: Destination::parse(options)?,
            profile: balance::hash(&text(options.remove("--profile"))?)?,
            reservation: id(&text(options.remove("--reservation"))?)?,
        })
    }
}

pub(super) fn execute(
    store: &WalletStore,
    publish: bool,
    options: Options,
) -> Result<serde_json::Value, Error> {
    if publish && store.recovery_required().map_err(storage)? {
        return Err(Error::RecoveryLocked);
    }
    let r = store
        .reservations()
        .map_err(storage)?
        .get(&options.reservation)
        .filter(|r| r.profile == options.profile)
        .ok_or(Error::Submission)?;
    let bytes = r.expose_transaction().ok_or(Error::Submission)?;
    let transaction = r.transaction.ok_or(Error::Submission)?;
    let mut inbox = Inbox::open(
        &options.destination.directory,
        &options.destination.inbox,
        options.profile,
        options.destination.node_key,
    )
    .map_err(|_| Error::Submission)?;
    let token = if publish {
        inbox.enqueue(bytes).map_err(|_| Error::Submission)?
    } else {
        monario_node::submission::digest(bytes)
    };
    let status = inbox.status(token).map_err(|_| Error::Submission)?;
    let lifecycle = inbox.lifecycle().map_err(|_| Error::Submission)?;
    Ok(serde_json::json!({
        "checkpoint":receipt(store.checkpoint().map_err(storage)?,store.recovery_required().map_err(storage)?),
        "validation_profile":hex(&options.profile),"node_public_key":hex(&options.destination.node_key),
        "reservation":hex(&options.reservation),"transaction_id":hex(&transaction),"submission":hex(&token),
        "published":status.is_some(),
        "last_observation":match status.as_ref().map(|s|s.state) {None=>"absent",Some(0)=>"queued",Some(1)=>"admitted-at-tip",Some(2)=>"not-admitted-at-tip",_=>return Err(Error::Submission)},
        "checked_tip":status.and_then(|s|s.checked_tip).map(|tip|hex(&tip)),
        "inbox_phase":match lifecycle.phase {0=>"active",1=>"staged",2=>"retired",_=>return Err(Error::Submission)},
        "inbox_peer":lifecycle.peer,
        "network_delivery_proven":false,"chain_confirmation_proven":false,
    }))
}
