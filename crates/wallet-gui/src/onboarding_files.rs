use crate::backend::{self, Network};
use std::io::{Read, Write};
use std::path::Path;

pub(crate) fn wallet_selection(path: &Path) -> Result<(String, String), String> {
    if !path.is_absolute() {
        return Err("Choose a wallet file from a local folder.".into());
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".monw"))
        .ok_or("Choose a Monario wallet or backup file (.monw).")?;
    backend::validate_name(name).map_err(|error| error.to_string())?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "The selected file could not be opened.")?;
    if !metadata.is_file() {
        return Err("Choose a regular wallet file.".into());
    }
    let directory = path
        .parent()
        .and_then(Path::to_str)
        .ok_or("The selected folder path is not supported.")?;
    backend::validate_directory(directory).map_err(|error| error.to_string())?;
    if directory.trim() != directory {
        return Err("The selected folder has leading or trailing whitespace.".into());
    }
    Ok((directory.into(), name.into()))
}

pub(crate) fn prepare_destination(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("Choose a wallet folder.".into());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err("The wallet location must be a regular folder.".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => builder
            .create(path)
            .map_err(|_| "The wallet folder could not be created.".into()),
        Err(_) => Err("The wallet folder could not be inspected.".into()),
    }
}

const MAX_RECEIPT_BYTES: u64 = 1024;

pub(crate) fn read_receipt(path: &Path, network: Network) -> Result<(String, u64), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "The receipt could not be opened.")?;
    if !meta.is_file() || meta.len() > MAX_RECEIPT_BYTES {
        return Err("Choose a regular Monario receipt file.".into());
    }
    let file = std::fs::File::open(path).map_err(|_| "The receipt could not be opened.")?;
    let mut text = String::new();
    file.take(MAX_RECEIPT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| "The receipt could not be read as text.")?;
    parse_receipt(&text, network)
}

pub(crate) fn parse_receipt(text: &str, network: Network) -> Result<(String, u64), String> {
    let invalid = "The file is not a Monario wallet or recovery receipt.";
    if text.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(invalid.into());
    }
    let mut lines = text.lines();
    if !matches!(
        lines.next(),
        Some("Monario recovery receipt" | "Monario wallet receipt")
    ) {
        return Err(invalid.into());
    }
    let receipt_network = lines
        .next()
        .and_then(|line| line.strip_prefix("Network: "))
        .ok_or(invalid)?;
    if receipt_network != network.as_str() {
        return Err(
            "The receipt belongs to a different network. Switch networks before opening it.".into(),
        );
    }
    let id = lines
        .next()
        .and_then(|line| line.strip_prefix("Wallet id: "))
        .ok_or(invalid)?;
    let revision = lines
        .next()
        .and_then(|line| line.strip_prefix("Revision: "))
        .ok_or(invalid)?;
    let number = revision.parse::<u64>().map_err(|_| invalid)?;
    if backend::validate_hex(id, 16, "wallet id").is_err()
        || number.to_string() != revision
        || lines.next().is_some()
    {
        return Err(invalid.into());
    }
    Ok((id.into(), number))
}

pub(crate) fn save_receipt(path: &Path, receipt: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "The receipt could not be created. Choose a new filename.")?;
    file.write_all(receipt.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "The receipt could not be saved. Choose a new filename and try again.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_requires_the_selected_network_and_exact_fields() {
        let id = "abcdef0123456789abcdef0123456789";
        let receipt = format!(
            "Monario recovery receipt\r\nNetwork: test\r\nWallet id: {id}\r\nRevision: 17\r\n"
        );
        assert_eq!(parse_receipt(&receipt, Network::Test), Ok((id.into(), 17)));
        assert!(parse_receipt(&receipt, Network::Main).is_err());
        assert!(parse_receipt(&receipt.replace("17", "+17"), Network::Test).is_err());
        assert!(parse_receipt(&(receipt + "Extra"), Network::Test).is_err());
    }

    #[test]
    fn chooser_resolves_wallet_name_and_receipt_save_does_not_overwrite() {
        let folder = std::env::temp_dir().join(format!(
            "monario-picker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        prepare_destination(&folder).unwrap();
        let wallet = folder.join("backup.monw");
        std::fs::write(&wallet, []).unwrap();
        assert_eq!(
            wallet_selection(&wallet),
            Ok((folder.to_str().unwrap().into(), "backup".into()))
        );
        let receipt = folder.join("receipt.txt");
        let original = "Monario wallet receipt\nNetwork: test\nWallet id: abcdef0123456789abcdef0123456789\nRevision: 0";
        save_receipt(&receipt, original).unwrap();
        assert!(wallet_selection(&receipt).is_err());
        assert!(save_receipt(&receipt, "replacement").is_err());
        assert_eq!(read_receipt(&receipt, Network::Test).unwrap().1, 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).unwrap();
            prepare_destination(&folder).unwrap();
            assert_eq!(
                std::fs::metadata(&folder).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        std::fs::remove_file(receipt).unwrap();
        std::fs::remove_file(wallet).unwrap();
        std::fs::remove_dir(folder).unwrap();
    }
}
