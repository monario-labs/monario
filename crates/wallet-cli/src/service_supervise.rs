//! Bounded smartnode supervision. One authenticated wallet, one password read
//! once from protected stdin and dropped after the store unlocks, one bounded
//! step per interval, and an optional stop file. No timer service, no credential
//! file, no env or argv secret, no socket and no automatic identity or inbox
//! switching. An optional health file lets an external monitor alert on staleness
//! or a failed step; it never contains a secret.
use super::*;
use std::{thread, time::Duration};

pub(super) struct Options {
    interval_ms: u64,
    max_steps: Option<u64>,
    stop: Option<String>,
    health: Option<String>,
}

impl Options {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        let seconds = number(&text(options.remove("--interval-seconds"))?)?;
        if !(1..=3600).contains(&seconds) {
            return Err(Error::Arguments);
        }
        let max_steps = options
            .remove("--max-steps")
            .map(|value| number(&text(Some(value))?))
            .transpose()?;
        if max_steps.is_some_and(|max| max == 0 || max > 1_000_000) {
            return Err(Error::Arguments);
        }
        let stop = options
            .remove("--stop-file")
            .map(|value| bounded_name(&text(Some(value))?, ".stop"))
            .transpose()?;
        let health = options
            .remove("--health-file")
            .map(|value| bounded_name(&text(Some(value))?, ".json"))
            .transpose()?;
        Ok(Self {
            interval_ms: seconds * 1_000,
            max_steps,
            stop,
            health,
        })
    }
}

/// Wallet names reject dots, so stop and health files have their own
/// basename-only rule: letters, digits, `_`, `-` and `.`, no leading or trailing
/// dot, no `..`, and a mandatory suffix.
fn bounded_name(value: &str, suffix: &str) -> Result<String, Error> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
        || !value.ends_with(suffix)
    {
        return Err(Error::Arguments);
    }
    Ok(value.to_owned())
}

/// A stop file must already exist as a regular, non-symlink file inside the
/// wallet directory. The supervisor never creates or removes it.
fn requested(stop: &Option<PathBuf>) -> bool {
    stop.as_ref().is_some_and(|path| {
        matches!(fs::symlink_metadata(path), Ok(meta) if meta.is_file() && !meta.file_type().is_symlink())
    })
}

/// Replace the public health record with a bounded JSON document. The record is
/// operational metadata (step count, state and checkpoint) and never contains a
/// password, seed or signed bytes. On Unix the file becomes owner-only.
fn write_health(path: &Option<PathBuf>, value: &serde_json::Value) -> Result<(), Error> {
    let Some(path) = path else {
        return Ok(());
    };
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Output)?;
    if bytes.len() > 16 * 1024 {
        return Err(Error::Output);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Output)?;
    let temp = path.with_file_name(format!(".{name}.tmp"));
    // A stale temp from a previous crash must not block the next record.
    let _ = fs::remove_file(&temp);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|_| Error::Output)?;
    let result = file
        .write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::Output)
        .and_then(|_| fs::rename(&temp, path).map_err(|_| Error::Output));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Drive the bounded loop with an injected step. Production injects the real
/// `service_step`; tests inject a counter, so max-step, stop-file, health-file
/// and error behaviour are testable without a wallet, chain or schedule.
pub(super) fn drive(
    stop: &Option<PathBuf>,
    health: &Option<PathBuf>,
    options: &Options,
    mut step: impl FnMut() -> Result<serde_json::Value, Error>,
    output: &mut impl Write,
) -> Result<(), Error> {
    let mut steps = 0u64;
    let mut last = serde_json::Value::Null;
    let reason;
    loop {
        if requested(stop) {
            reason = "stop_file";
            break;
        }
        // A step error stops supervision rather than retrying blindly;
        // waiting/no-funding are successful step results, not errors.
        let value = match step() {
            Ok(value) => value,
            Err(error) => {
                // Fail closed on the report too: a record that cannot be
                // written is an output failure, exactly as on the success path.
                write_health(
                    health,
                    &serde_json::json!({"service":"supervise","healthy":false,
                    "steps":steps.to_string(),"stopped":"error","error":error.message()}),
                )?;
                return Err(error);
            }
        };
        report(&value, output)?;
        steps += 1;
        write_health(
            health,
            &serde_json::json!({"service":"supervise","healthy":true,
                "steps":steps.to_string(),"stopped":false,"last":&value}),
        )?;
        last = value;
        if options.max_steps.is_some_and(|max| steps >= max) {
            reason = "max_steps";
            break;
        }
        let mut remaining = options.interval_ms;
        let mut stopped = false;
        while remaining > 0 {
            if requested(stop) {
                stopped = true;
                break;
            }
            let slice = remaining.min(250);
            thread::sleep(Duration::from_millis(slice));
            remaining -= slice;
        }
        if stopped {
            reason = "stop_file";
            break;
        }
    }
    report(
        &serde_json::json!({"service":"supervise","stopped":true,"reason":reason,
        "steps":steps.to_string(),"signed":false,"socket_opened":false,
        "credentials_persisted":false}),
        output,
    )?;
    write_health(
        health,
        &serde_json::json!({"service":"supervise","healthy":true,
            "steps":steps.to_string(),"stopped":reason,"last":last}),
    )
}

pub(super) fn execute(
    root: &Path,
    store: &mut WalletStore,
    account: u32,
    scan: balance::Options,
    step: service_step::Options,
    options: Options,
    output: &mut impl Write,
) -> Result<(), Error> {
    let stop = options.stop.as_ref().map(|file| root.join(file));
    let health = options.health.as_ref().map(|file| root.join(file));
    drive(
        &stop,
        &health,
        &options,
        || service_step::execute(root, store, account, scan.clone(), step.clone()),
        output,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(pairs: &[(&str, &str)]) -> Result<Options, Error> {
        let mut map: BTreeMap<String, OsString> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), OsString::from(*value)))
            .collect();
        Options::parse(&mut map)
    }

    fn options(interval_ms: u64, max_steps: Option<u64>) -> Options {
        Options {
            interval_ms,
            max_steps,
            stop: None,
            health: None,
        }
    }

    fn lines(output: &[u8]) -> usize {
        output.iter().filter(|byte| **byte == b'\n').count()
    }

    #[test]
    fn interval_steps_and_stop_file_are_bounded() {
        let valid = parsed(&[
            ("--interval-seconds", "30"),
            ("--max-steps", "4"),
            ("--stop-file", "pool.stop"),
            ("--health-file", "pool-health.json"),
        ])
        .unwrap();
        assert_eq!(valid.interval_ms, 30_000);
        assert_eq!(valid.max_steps, Some(4));
        assert_eq!(valid.stop.as_deref(), Some("pool.stop"));
        assert_eq!(valid.health.as_deref(), Some("pool-health.json"));

        assert!(parsed(&[("--interval-seconds", "0")]).is_err());
        assert!(parsed(&[("--interval-seconds", "3601")]).is_err());
        assert!(parsed(&[]).is_err());
        assert!(parsed(&[("--interval-seconds", "1"), ("--max-steps", "0")]).is_err());
        assert!(parsed(&[("--interval-seconds", "1"), ("--stop-file", "stop.json")]).is_err());
        assert!(
            parsed(&[
                ("--interval-seconds", "1"),
                ("--stop-file", "../escape.stop")
            ])
            .is_err()
        );
        assert!(
            parsed(&[
                ("--interval-seconds", "1"),
                ("--health-file", "health.stop")
            ])
            .is_err()
        );
        assert!(
            parsed(&[
                ("--interval-seconds", "1"),
                ("--health-file", "../escape.json")
            ])
            .is_err()
        );
    }

    #[test]
    fn max_steps_bounds_the_loop_and_reports_the_stop_line() {
        let mut calls = 0u64;
        let mut output = Vec::new();
        drive(
            &None,
            &None,
            &options(1, Some(3)),
            || {
                calls += 1;
                Ok(serde_json::json!({"state":"waiting"}))
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(lines(&output), 4);
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(r#""steps":"3""#));
        assert!(text.contains(r#""stopped":true"#));
        assert!(text.contains(r#""reason":"max_steps""#));
    }

    #[test]
    fn stop_file_before_start_runs_no_step() {
        let dir = tempfile::tempdir().unwrap();
        let stop = Some(dir.path().join("halt.stop"));
        fs::write(stop.as_ref().unwrap(), b"stop").unwrap();
        let mut calls = 0u64;
        let mut output = Vec::new();
        drive(
            &stop,
            &None,
            &options(1, None),
            || {
                calls += 1;
                Ok(serde_json::json!({"state":"waiting"}))
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(calls, 0);
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains(r#""steps":"0""#)
        );
    }

    #[test]
    fn stop_file_during_the_wait_prevents_the_next_step() {
        let dir = tempfile::tempdir().unwrap();
        let stop = dir.path().join("halt.stop");
        let signal = stop.clone();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            fs::write(&signal, b"stop").unwrap();
        });
        let mut calls = 0u64;
        let mut output = Vec::new();
        drive(
            &Some(stop),
            &None,
            &options(60_000, None),
            || {
                calls += 1;
                Ok(serde_json::json!({"state":"waiting"}))
            },
            &mut output,
        )
        .unwrap();
        writer.join().unwrap();
        assert_eq!(calls, 1, "the wait must be interrupted by the stop file");
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains(r#""steps":"1""#)
        );
    }

    #[test]
    fn step_error_stops_without_retrying() {
        let mut calls = 0u64;
        let mut output = Vec::new();
        let result = drive(
            &None,
            &None,
            &options(1, Some(5)),
            || {
                calls += 1;
                Err(Error::Transaction)
            },
            &mut output,
        );
        assert!(matches!(result, Err(Error::Transaction)));
        assert_eq!(calls, 1);
        assert!(output.is_empty());
    }

    #[test]
    fn health_file_reports_each_step_and_the_stop_reason() {
        let dir = tempfile::tempdir().unwrap();
        let health = Some(dir.path().join("supervise-health.json"));
        fs::write(health.as_ref().unwrap(), b"stale record").unwrap();
        let mut output = Vec::new();
        drive(
            &None,
            &health,
            &options(1, Some(2)),
            || Ok(serde_json::json!({"state":"waiting","created":false})),
            &mut output,
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(health.as_ref().unwrap()).unwrap()).unwrap();
        assert_eq!(value["service"], "supervise");
        assert_eq!(value["healthy"], true);
        assert_eq!(value["steps"], "2");
        assert_eq!(value["stopped"], "max_steps");
        assert_eq!(value["last"]["state"], "waiting");
        assert_eq!(value["last"]["created"], false);
    }

    #[test]
    fn unwritable_health_file_stops_supervision() {
        let dir = tempfile::tempdir().unwrap();
        let health = Some(dir.path().to_path_buf());
        let mut calls = 0u64;
        let mut output = Vec::new();
        let result = drive(
            &None,
            &health,
            &options(1, Some(5)),
            || {
                calls += 1;
                Ok(serde_json::json!({"state":"waiting"}))
            },
            &mut output,
        );
        assert!(matches!(result, Err(Error::Output)));
        assert_eq!(calls, 1);
        assert_eq!(lines(&output), 1);
    }

    #[test]
    fn health_file_records_a_step_error_without_retrying() {
        let dir = tempfile::tempdir().unwrap();
        let health = Some(dir.path().join("supervise-health.json"));
        let mut output = Vec::new();
        let result = drive(
            &None,
            &health,
            &options(1, Some(5)),
            || Err(Error::Transaction),
            &mut output,
        );
        assert!(matches!(result, Err(Error::Transaction)));
        assert!(output.is_empty());
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(health.as_ref().unwrap()).unwrap()).unwrap();
        assert_eq!(value["healthy"], false);
        assert_eq!(value["stopped"], "error");
        assert_eq!(value["steps"], "0");
        assert_eq!(
            value["error"],
            "transaction request invalid or construction unavailable; inspect reservations before retrying"
        );
    }
}
