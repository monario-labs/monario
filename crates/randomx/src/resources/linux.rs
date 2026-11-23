//! Linux memory-availability probe for the mining worker budget.
//!
//! The host figure comes from `MemAvailable`. On top of that the process may
//! live inside a cgroup hierarchy that caps its memory, in which case the
//! remaining headroom of every enclosing memory scope (v1 or v2) is the real
//! ceiling. Detection is deliberately conservative: once a memory controller
//! is known to enclose the process, any failure to read that scope yields
//! `None` instead of trusting the host figure. Only a genuinely absent
//! controller file is skipped, and the memory controller is honoured in the
//! single hierarchy that owns it.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

const PROC_MEMINFO: &str = "/proc/meminfo";
const PROC_CGROUP: &str = "/proc/self/cgroup";
const PROC_MOUNTINFO: &str = "/proc/self/mountinfo";

/// Bounds for pseudo-file reads. Every file consulted here is small, so a
/// larger file means the kernel layout is not what we expect and the read is
/// discarded rather than truncated.
const MEMINFO_LIMIT: u64 = 64 * 1024;
const CGROUP_LIMIT: u64 = 64 * 1024;
const MOUNTINFO_LIMIT: u64 = 256 * 1024;
const CONTROLLER_LIMIT: u64 = 64;

/// Upper bound on the number of ancestors inspected per hierarchy. Real
/// hierarchies are shallow; this keeps a hostile path from causing reads.
const MAX_ANCESTORS: usize = 64;

const V2_LIMIT: &str = "memory.max";
const V2_USAGE: &str = "memory.current";
const V2_UNLIMITED: &str = "max";

const V1_LIMIT: &str = "memory.limit_in_bytes";
const V1_USAGE: &str = "memory.usage_in_bytes";
/// cgroup v1 reports "no limit" as `LONG_MAX` rounded down to the page size,
/// that is `2^63 - page_size`. Kernels in the wild use 4 KiB, 16 KiB or 64 KiB
/// pages, so any value from `2^63 - 64 KiB` upwards is a sentinel rather than
/// a real cap.
const V1_UNLIMITED_THRESHOLD: u64 = 0x7FFF_FFFF_FFFF_0000;

/// Memory available to the miner, clamped by the cgroup memory limits that
/// enclose this process.
pub(super) fn available_bytes() -> Option<u64> {
    let meminfo = read_bounded(Path::new(PROC_MEMINFO), MEMINFO_LIMIT).ok()?;
    let free = parse_mem_available(&meminfo)?;

    // Without a membership record there is no controller to honour, and the
    // host figure already accounts for the rest of the machine. A record that
    // exists but cannot be trusted (permissions, oversized content, invalid
    // UTF-8) is a different case: a container's limits may well be hidden
    // behind it, so fail closed instead of trusting the host figure.
    let membership = match read_bounded(Path::new(PROC_CGROUP), CGROUP_LIMIT) {
        Ok(membership) => membership,
        Err(ReadFailure::Missing) => return Some(free),
        Err(ReadFailure::Failed) => return None,
    };
    let memberships = parse_cgroup(&membership)?;
    if memberships.v2.is_none() && memberships.v1.is_none() {
        return Some(free);
    }

    // A membership names a controller, so the mounts must be readable to map
    // it onto the filesystem. Failing here is conservative by design.
    let mountinfo = read_bounded(Path::new(PROC_MOUNTINFO), MOUNTINFO_LIMIT).ok()?;
    let mounts = parse_mountinfo(&mountinfo)?;
    apply(free, &memberships, &mounts, |path: &Path| {
        read_bounded(path, CONTROLLER_LIMIT)
    })
}

/// Why a controller file could not be read. Absence is kept apart from other
/// failures because a cgroup that does not carry the memory controller has no
/// such file at all, while a permission, I/O or encoding error means this
/// view of the hierarchy cannot be trusted.
#[derive(Clone, Copy, Debug)]
enum ReadFailure {
    /// The file (or a parent directory of it) does not exist.
    Missing,
    /// Any other failure: permissions, oversized content, invalid UTF-8.
    Failed,
}

impl ReadFailure {
    fn from_io(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => Self::Missing,
            _ => Self::Failed,
        }
    }
}

/// Reads at most `limit` bytes. A file that does not fit is rejected instead
/// of being silently truncated.
fn read_bounded(path: &Path, limit: u64) -> Result<String, ReadFailure> {
    let file = std::fs::File::open(path).map_err(ReadFailure::from_io)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(ReadFailure::from_io)?;
    if bytes.len() as u64 > limit {
        return Err(ReadFailure::Failed);
    }
    String::from_utf8(bytes).map_err(|_| ReadFailure::Failed)
}

fn parse_mem_available(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|line| {
        line.strip_prefix("MemAvailable:")?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)
    })
}

#[derive(Default)]
struct Memberships {
    v2: Option<PathBuf>,
    v1: Option<PathBuf>,
}

/// Extracts the unified (v2) and memory-controller (v1) membership paths.
/// A path that cannot be normalized safely rejects the whole record.
fn parse_cgroup(text: &str) -> Option<Memberships> {
    let mut memberships = Memberships::default();
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(_id), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if controllers.is_empty() {
            if memberships.v2.is_none() {
                memberships.v2 = Some(normalize(path)?);
            }
        } else if memberships.v1.is_none() && controllers.split(',').any(|name| name == "memory") {
            memberships.v1 = Some(normalize(path)?);
        }
    }
    Some(memberships)
}

#[derive(Default)]
struct Mounts {
    v1: Vec<Mount>,
    v2: Vec<Mount>,
}

/// A cgroup mount: `root` is the subtree of the hierarchy the mount exposes,
/// `point` is where it is attached in this mount namespace.
struct Mount {
    root: PathBuf,
    point: PathBuf,
}

/// Parses `/proc/self/mountinfo`, decoding octal escapes and keeping only
/// cgroup mounts. A cgroup mount that cannot be decoded rejects the record,
/// because ignoring it could silently drop a memory limit.
fn parse_mountinfo(text: &str) -> Option<Mounts> {
    let mut mounts = Mounts::default();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(separator) = fields.iter().position(|field| *field == "-") else {
            continue;
        };
        // 6 mandatory fields before the optional ones, 3 after the separator.
        if separator < 6 || fields.len() < separator + 4 {
            continue;
        }
        let fstype = fields[separator + 1];
        let cgroup2 = fstype == "cgroup2";
        if !cgroup2 && fstype != "cgroup" {
            continue;
        }
        let root = decode_field(fields[3])?;
        let point = decode_field(fields[4])?;
        if cgroup2 {
            mounts.v2.push(Mount { root, point });
            continue;
        }
        // For v1 the super options list the controllers the mount carries.
        if fields[separator + 3]
            .split(',')
            .any(|name| name == "memory")
        {
            mounts.v1.push(Mount { root, point });
        }
    }
    Some(mounts)
}

/// Decodes the octal escapes mountinfo uses for spaces, tabs, newlines and
/// backslashes, then requires a path without `.` or `..` components.
fn decode_field(raw: &str) -> Option<PathBuf> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            let digits = bytes.get(index + 1..index + 4)?;
            let mut value = 0u16;
            for digit in digits {
                if !(b'0'..=b'7').contains(digit) {
                    return None;
                }
                value = value * 8 + u16::from(digit - b'0');
            }
            decoded.push(u8::try_from(value).ok()?);
            index += 4;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    let text = String::from_utf8(decoded).ok()?;
    normalize(&text)
}

/// Builds a path out of normal components only, so no joined path can escape
/// its mount point.
fn normalize(raw: &str) -> Option<PathBuf> {
    let mut components = Path::new(raw).components();
    let mut path = PathBuf::new();
    match components.next()? {
        Component::RootDir => path.push(Component::RootDir.as_os_str()),
        Component::Normal(part) => path.push(part),
        _ => return None,
    }
    for component in components {
        match component {
            Component::Normal(part) => path.push(part),
            _ => return None,
        }
    }
    Some(path)
}

fn apply<F>(free: u64, memberships: &Memberships, mounts: &Mounts, read: F) -> Option<u64>
where
    F: Fn(&Path) -> Result<String, ReadFailure>,
{
    // The memory controller can be attached to only one hierarchy. On hybrid
    // systems that is v1, and the unified hierarchy then exposes no memory
    // files at all, so v1 alone decides the ceiling.
    if let Some(membership) = &memberships.v1 {
        let mount = select(&mounts.v1, membership)?;
        let group = resolve(mount, membership)?;
        return clamp_v1(free, &group, &mount.point, &read);
    }
    let Some(membership) = &memberships.v2 else {
        return Some(free);
    };
    let mount = select(&mounts.v2, membership)?;
    let group = resolve(mount, membership)?;
    clamp_v2(free, &group, &mount.point, &read)
}

/// Picks the mount whose subtree contains the membership path. The least
/// specific root wins: a bind mount of a subdirectory hides everything above
/// it, so preferring the deepest root would lose quotas the wider mount still
/// exposes.
fn select<'a>(mounts: &'a [Mount], membership: &Path) -> Option<&'a Mount> {
    mounts
        .iter()
        .filter(|mount| membership.strip_prefix(&mount.root).is_ok())
        .min_by_key(|mount| {
            (
                mount.root.components().count(),
                mount.point.components().count(),
            )
        })
}

/// Maps a membership path onto the mounted hierarchy. The membership is
/// relative to the mount's root, so the remainder is appended to the mount
/// point; a path that would leave the mount is rejected.
fn resolve(mount: &Mount, membership: &Path) -> Option<PathBuf> {
    let relative = membership.strip_prefix(&mount.root).ok()?;
    let group = mount.point.join(relative);
    group.starts_with(&mount.point).then_some(group)
}

fn clamp_v2<F>(mut available: u64, group: &Path, base: &Path, read: &F) -> Option<u64>
where
    F: Fn(&Path) -> Result<String, ReadFailure>,
{
    let mut scope = group.to_path_buf();
    for _ in 0..MAX_ANCESTORS {
        if !scope.starts_with(base) {
            return None;
        }
        // The true hierarchy root has no `memory.max`, and a descendant whose
        // memory controller is disabled has none either. Both are normally
        // absent files, so keep walking towards the mount root instead of
        // giving up; a real I/O error still fails closed.
        match read(&scope.join(V2_LIMIT)) {
            Ok(limit) => {
                let limit = limit.trim();
                if limit != V2_UNLIMITED {
                    let limit = limit.parse::<u64>().ok()?;
                    // A finite limit we cannot subtract usage from is not a
                    // limit we can honour.
                    let used = read(&scope.join(V2_USAGE)).ok()?;
                    let used = used.trim().parse::<u64>().ok()?;
                    available = available.min(limit.saturating_sub(used));
                }
            }
            Err(ReadFailure::Missing) => {}
            Err(ReadFailure::Failed) => return None,
        }
        if scope == base {
            return Some(available);
        }
        scope = scope.parent()?.to_path_buf();
    }
    None
}

fn clamp_v1<F>(mut available: u64, group: &Path, base: &Path, read: &F) -> Option<u64>
where
    F: Fn(&Path) -> Result<String, ReadFailure>,
{
    let mut scope = group.to_path_buf();
    for _ in 0..MAX_ANCESTORS {
        if !scope.starts_with(base) {
            return None;
        }
        // The v1 memory hierarchy creates the limit file in every cgroup, so
        // absence here means this view of the tree is wrong: fail closed.
        let limit = read(&scope.join(V1_LIMIT)).ok()?;
        let limit = limit.trim().parse::<u64>().ok()?;
        if limit < V1_UNLIMITED_THRESHOLD {
            let used = read(&scope.join(V1_USAGE)).ok()?;
            let used = used.trim().parse::<u64>().ok()?;
            available = available.min(limit.saturating_sub(used));
        }
        if scope == base {
            return Some(available);
        }
        scope = scope.parent()?.to_path_buf();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves controller files from a fixed table, like a fake cgroup tree.
    /// Every path that is not listed is absent, exactly as it is in a cgroup
    /// that does not carry the memory controller.
    fn reader<'a>(
        files: &'a [(&'a str, &'a str)],
    ) -> impl Fn(&Path) -> Result<String, ReadFailure> + 'a {
        move |path: &Path| {
            files
                .iter()
                .find(|(name, _)| Path::new(*name) == path)
                .map_or(
                    Err(ReadFailure::Missing),
                    |(_, body)| Ok((*body).to_owned()),
                )
        }
    }

    /// Like `reader`, but the listed paths exist and cannot be read.
    fn failing<'a>(
        files: &'a [(&'a str, &'a str)],
        unreadable: &'a [&'a str],
    ) -> impl Fn(&Path) -> Result<String, ReadFailure> + 'a {
        move |path: &Path| {
            if unreadable.iter().any(|name| Path::new(*name) == path) {
                return Err(ReadFailure::Failed);
            }
            reader(files)(path)
        }
    }

    #[test]
    fn mem_available_is_kib_and_garbage_is_rejected() {
        let meminfo = "MemTotal:       16384000 kB\nMemAvailable:    4096000 kB\n";
        assert_eq!(parse_mem_available(meminfo), Some(4_096_000 * 1024));
        assert_eq!(parse_mem_available("MemFree: 1 kB\n"), None);
        assert_eq!(parse_mem_available("MemAvailable: bogus kB\n"), None);
    }

    #[test]
    fn mountinfo_decodes_escapes_and_keeps_only_memory_mounts() {
        let text = concat!(
            "25 1 0:24 / / rw,relatime - ext4 /dev/root rw\n",
            "30 25 0:30 /docker/abc /sys/fs/cgroup/mem\\040ory rw,nosuid - cgroup cgroup rw,memory\n",
            "31 25 0:31 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw,nsdelegate\n",
            "32 25 0:32 / /sys/fs/cgroup/cpu rw,nosuid - cgroup cgroup rw,cpu,cpuacct\n",
        );
        let mounts = parse_mountinfo(text).expect("parsed");
        assert_eq!(mounts.v1.len(), 1);
        assert_eq!(mounts.v2.len(), 1);
        assert_eq!(mounts.v1[0].root, PathBuf::from("/docker/abc"));
        assert_eq!(mounts.v1[0].point, PathBuf::from("/sys/fs/cgroup/mem ory"));
    }

    #[test]
    fn v2_clamps_every_ancestor_and_skips_unlimited() {
        let memberships = parse_cgroup("0::/docker/abc/worker\n").expect("membership");
        let mounts = parse_mountinfo("31 25 0:31 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n")
            .expect("mounts");
        // The hierarchy root is included by the mount and has no memory.max.
        let files = [
            ("/sys/fs/cgroup/docker/memory.max", "2000"),
            ("/sys/fs/cgroup/docker/memory.current", "300"),
            ("/sys/fs/cgroup/docker/abc/memory.max", "900"),
            ("/sys/fs/cgroup/docker/abc/memory.current", "400"),
            ("/sys/fs/cgroup/docker/abc/worker/memory.max", "max"),
        ];
        // 900 - 400 headroom wins over the 2000 - 300 parent and the host.
        assert_eq!(
            apply(4096, &memberships, &mounts, reader(&files)),
            Some(500)
        );
    }

    #[test]
    fn v2_skips_absent_limits_but_keeps_walking_ancestors() {
        let mounts = parse_mountinfo("31 25 0:31 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n")
            .expect("mounts");
        let memberships = parse_cgroup("0::/docker/abc/worker\n").expect("membership");

        // Neither the leaf nor its parent enables the memory controller, so
        // both lack memory.max; only /docker carries a quota.
        let disabled = [
            ("/sys/fs/cgroup/docker/memory.max", "2000"),
            ("/sys/fs/cgroup/docker/memory.current", "300"),
        ];
        assert_eq!(
            apply(4096, &memberships, &mounts, reader(&disabled)),
            Some(1700)
        );

        // A membership equal to the mounted root has no files above it at
        // all, which must not be mistaken for an unreadable hierarchy.
        let root = parse_cgroup("0::/\n").expect("membership");
        assert_eq!(apply(4096, &root, &mounts, reader(&[])), Some(4096));
    }

    #[test]
    fn hybrid_membership_uses_v1_and_ignores_v2() {
        let memberships =
            parse_cgroup("0::/docker/abc\n7:memory:/docker/abc\n").expect("membership");
        let mounts = parse_mountinfo(concat!(
            "31 25 0:31 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            "30 25 0:30 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
        ))
        .expect("mounts");

        // A finite unified pair with only 50 bytes of headroom: it must never
        // be consulted, because the controller is attached to v1 and the
        // unified hierarchy cannot own it.
        let misleading = [
            ("/sys/fs/cgroup/docker/abc/memory.max", "1000"),
            ("/sys/fs/cgroup/docker/abc/memory.current", "950"),
            (
                "/sys/fs/cgroup/memory/memory.limit_in_bytes",
                "9223372036854771712",
            ),
            (
                "/sys/fs/cgroup/memory/docker/memory.limit_in_bytes",
                "9223372036854771712",
            ),
            (
                "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes",
                "256",
            ),
            (
                "/sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes",
                "156",
            ),
        ];
        assert_eq!(
            apply(4096, &memberships, &mounts, reader(&misleading)),
            Some(100)
        );

        // The realistic hybrid tree: the unified mount carries no memory
        // files at all, so only the v1 limit matters.
        let realistic = [
            (
                "/sys/fs/cgroup/memory/memory.limit_in_bytes",
                "9223372036854771712",
            ),
            (
                "/sys/fs/cgroup/memory/docker/memory.limit_in_bytes",
                "9223372036854771712",
            ),
            (
                "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes",
                "256",
            ),
            (
                "/sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes",
                "156",
            ),
        ];
        assert_eq!(
            apply(4096, &memberships, &mounts, reader(&realistic)),
            Some(100)
        );
    }

    #[test]
    fn v1_sentinel_is_unlimited_and_usage_still_clamps() {
        let memberships = parse_cgroup("7:memory:/docker/abc\n").expect("membership");
        let mounts = parse_mountinfo(
            "30 25 0:30 /docker /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
        )
        .expect("mounts");
        let files = [
            (
                "/sys/fs/cgroup/memory/abc/memory.limit_in_bytes",
                "9223372036854771712",
            ),
            ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "600"),
            ("/sys/fs/cgroup/memory/memory.usage_in_bytes", "100"),
        ];
        // The process scope is unlimited, so only the parent's headroom counts.
        assert_eq!(
            apply(4096, &memberships, &mounts, reader(&files)),
            Some(500)
        );

        let finite = [
            ("/sys/fs/cgroup/memory/abc/memory.limit_in_bytes", "256"),
            ("/sys/fs/cgroup/memory/abc/memory.usage_in_bytes", "156"),
            ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "600"),
            ("/sys/fs/cgroup/memory/memory.usage_in_bytes", "100"),
        ];
        assert_eq!(
            apply(4096, &memberships, &mounts, reader(&finite)),
            Some(100)
        );
    }

    #[test]
    fn v1_sentinel_is_recognized_for_every_page_size() {
        let memberships = parse_cgroup("7:memory:/docker/abc\n").expect("membership");
        let mounts =
            parse_mountinfo("30 25 0:30 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n")
                .expect("mounts");

        // `2^63 - page_size` for 4 KiB, 16 KiB and 64 KiB pages.
        let sentinels = [
            "9223372036854771712",
            "9223372036854759424",
            "9223372036854710272",
        ];
        for sentinel in sentinels {
            let files = [
                ("/sys/fs/cgroup/memory/memory.limit_in_bytes", sentinel),
                ("/sys/fs/cgroup/memory/docker/memory.limit_in_bytes", "600"),
                ("/sys/fs/cgroup/memory/docker/memory.usage_in_bytes", "100"),
                (
                    "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes",
                    sentinel,
                ),
            ];
            assert_eq!(
                apply(4096, &memberships, &mounts, reader(&files)),
                Some(500),
                "sentinel {sentinel}"
            );
        }
    }

    #[test]
    fn bind_submount_does_not_hide_reachable_ancestor_quota() {
        let memberships = parse_cgroup("0::/docker/abc/worker\n").expect("membership");
        let mounts = parse_mountinfo(concat!(
            "31 25 0:31 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            "33 31 0:31 /docker/abc /sys/fs/cgroup/docker/abc rw - cgroup2 cgroup2 rw\n",
        ))
        .expect("mounts");

        // The wider mount is picked, so the quota above the bind mount stays
        // visible instead of being cut off at /docker/abc.
        let chosen = select(&mounts.v2, Path::new("/docker/abc/worker"));
        assert_eq!(
            chosen.map(|mount| mount.root.clone()),
            Some(PathBuf::from("/"))
        );

        let files = [
            ("/sys/fs/cgroup/docker/memory.max", "1000"),
            ("/sys/fs/cgroup/docker/memory.current", "500"),
            ("/sys/fs/cgroup/docker/abc/memory.max", "2000"),
            ("/sys/fs/cgroup/docker/abc/memory.current", "0"),
            ("/sys/fs/cgroup/docker/abc/worker/memory.max", "max"),
        ];
        assert_eq!(
            apply(4096, &memberships, &mounts, reader(&files)),
            Some(500)
        );
    }

    #[test]
    fn escaping_membership_or_unreadable_scope_is_rejected() {
        let mounts = parse_mountinfo("31 25 0:31 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n")
            .expect("mounts");

        // A membership path that could escape its mount is not trusted.
        assert!(parse_cgroup("0::/../../etc\n").is_none());

        // A detected controller with no matching mount cannot be honoured.
        let orphan = parse_cgroup("0::/docker/abc\n").expect("membership");
        let host_only = parse_mountinfo("25 1 0:24 / / rw - ext4 /dev/root rw\n").expect("mounts");
        assert_eq!(
            apply(4096, &orphan, &host_only, |_: &Path| {
                Err(ReadFailure::Missing)
            }),
            None
        );

        // A limit without a readable usage counter fails instead of guessing.
        let memberships = parse_cgroup("0::/docker\n").expect("membership");
        let partial = [("/sys/fs/cgroup/docker/memory.max", "900")];
        assert_eq!(apply(4096, &memberships, &mounts, reader(&partial)), None);
    }

    #[test]
    fn absence_and_io_failure_are_not_interchangeable() {
        let mounts = parse_mountinfo("31 25 0:31 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n")
            .expect("mounts");
        let memberships = parse_cgroup("0::/docker\n").expect("membership");

        let complete = [
            ("/sys/fs/cgroup/memory.max", "1000"),
            ("/sys/fs/cgroup/memory.current", "250"),
        ];
        assert_eq!(
            apply(4096, &memberships, &mounts, reader(&complete)),
            Some(750)
        );

        // The same tree, but the limit exists and cannot be read: absence is
        // normal for v2, an I/O error is not.
        let denied_limit = ["/sys/fs/cgroup/memory.max"];
        assert_eq!(
            apply(
                4096,
                &memberships,
                &mounts,
                failing(&complete, &denied_limit)
            ),
            None
        );

        // A finite limit whose usage counter is unreadable also fails closed.
        let denied_usage = ["/sys/fs/cgroup/memory.current"];
        assert_eq!(
            apply(
                4096,
                &memberships,
                &mounts,
                failing(&complete, &denied_usage)
            ),
            None
        );

        // Parse errors cannot be mistaken for "unlimited" either.
        let garbage = [("/sys/fs/cgroup/memory.max", "lots")];
        assert_eq!(apply(4096, &memberships, &mounts, reader(&garbage)), None);
        let bad_usage = [
            ("/sys/fs/cgroup/memory.max", "1000"),
            ("/sys/fs/cgroup/memory.current", "some"),
        ];
        assert_eq!(apply(4096, &memberships, &mounts, reader(&bad_usage)), None);

        // v1 always creates the limit file, so absence there is a broken view.
        let v1_mounts =
            parse_mountinfo("30 25 0:30 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n")
                .expect("mounts");
        let v1 = parse_cgroup("7:memory:/docker\n").expect("membership");
        assert_eq!(apply(4096, &v1, &v1_mounts, reader(&[])), None);
    }
}
