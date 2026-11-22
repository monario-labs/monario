//! Authenticated offline files only; never constructs a node or transport.
use super::*;
use monario_chain::transfer;
use std::fs::OpenOptions;

const MAX_PAGE_BYTES: u64 = 74 + 128 * (4 + 5_000_000);

pub(super) fn execute(
    command: &Command,
    root: &Path,
    chain_path: &Path,
    cp: Checkpoint,
    chain: &mut DurableChain<V6Verifier>,
    now: u64,
    output: &mut impl Write,
) -> Result<(), Error> {
    let name = command.block_file.as_deref().ok_or(Error::Arguments)?;
    if chain_path
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case(name))
        || command
            .manifest
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case(name))
    {
        return Err(Error::Configuration);
    }
    let path = root.join(name);
    let (end, count, accepted, known) = if command.action == Action::BlocksExport {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|_| Error::Configuration)?;
        let page = transfer::export(chain, command.after.ok_or(Error::Arguments)?, &mut file)
            .map_err(|_| Error::Transfer)?;
        file.sync_all().map_err(|_| Error::Storage)?;
        #[cfg(unix)]
        File::open(root)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| Error::Storage)?;
        (page.end, page.blocks, None, None)
    } else {
        regular(&path)?;
        let file = File::open(&path).map_err(|_| Error::Configuration)?;
        regular(&path)?;
        let meta = file.metadata().map_err(|_| Error::Configuration)?;
        if !meta.is_file() || !(74..=MAX_PAGE_BYTES).contains(&meta.len()) {
            return Err(Error::Configuration);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let current = fs::symlink_metadata(&path).map_err(|_| Error::Configuration)?;
            if meta.nlink() != 1 || meta.dev() != current.dev() || meta.ino() != current.ino() {
                return Err(Error::Configuration);
            }
        }
        let imported = transfer::import(chain, &mut file.take(MAX_PAGE_BYTES + 1), now)
            .map_err(|_| Error::Transfer)?;
        (
            imported.end,
            imported.accepted + imported.known,
            Some(imported.accepted),
            Some(imported.known),
        )
    };
    chain.checkpoint().map_err(|_| Error::Storage)?;
    let validated = chain.chain().map_err(|_| Error::Storage)?;
    report(
        &serde_json::json!({
            "operation":if command.action == Action::BlocksExport { "blocks-export" } else { "blocks-import" },
            "profile":hex(&cp.profile),"public_key":hex(&cp.public_key),"revision":cp.revision,
            "block_file":name,"end":hex(&end),"blocks":count,"accepted":accepted,"known":known,
            "validated_tip":hex(&validated.tip()),"height":validated.height().to_string(),
            "chain_checkpoint":command.state_checkpoint.map(|pin| hex(&pin)),
            "full_chain_replay":command.state_checkpoint.is_none(),"network_started":false
        }),
        output,
    )
}
