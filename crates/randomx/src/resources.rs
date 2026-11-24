//! Local mining resource policy shared by the node CLI and wallet.

// Platform probes live in their own files, referenced by explicit paths so they
// also resolve under a standalone `rustc` invocation. The macOS file keeps its
// pure helpers testable, so its tests run on other hosts too.
#[cfg(target_os = "linux")]
#[path = "resources/linux.rs"]
mod linux;
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[path = "resources/macos.rs"]
mod macos;

const MIB: u64 = 1024 * 1024;
const CACHE_BYTES: u64 = 256 * MIB;
const WORKER_BUDGET: u64 = 4 * MIB;

/// Absolute local process limit. Hardware can lower it.
pub const MAX_WORKERS: u8 = 128;

/// Logical CPUs, bounded by available RAM and an absolute process limit.
/// Each VM needs a 2 MiB scratchpad. Budget 4 MiB for VM and thread overhead,
/// and leave half the available RAM for the node, OS and other applications.
pub fn mining_worker_limit() -> u8 {
    let cpu = std::thread::available_parallelism().map_or(1, usize::from);
    worker_limit(cpu, available_bytes())
}

fn worker_limit(cpu: usize, available: Option<u64>) -> u8 {
    // On unsupported platforms offer only the minimum profile. Unsupported
    // memory reporting must not enable the high-parallelism path.
    let memory = available.map_or(1, |bytes| {
        (bytes / 2).saturating_sub(CACHE_BYTES) / WORKER_BUDGET
    });
    cpu.min(memory.min(u64::from(MAX_WORKERS)) as usize) as u8
}

#[cfg(target_os = "linux")]
fn available_bytes() -> Option<u64> {
    linux::available_bytes()
}

#[cfg(target_os = "windows")]
fn available_bytes() -> Option<u64> {
    #[repr(C)]
    #[derive(Default)]
    struct MemoryStatus {
        length: u32,
        load: u32,
        total_physical: u64,
        available_physical: u64,
        total_pagefile: u64,
        available_pagefile: u64,
        total_virtual: u64,
        available_virtual: u64,
        extended_virtual: u64,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalMemoryStatusEx(status: *mut MemoryStatus) -> i32;
    }
    let mut status = MemoryStatus {
        length: std::mem::size_of::<MemoryStatus>() as u32,
        ..MemoryStatus::default()
    };
    // SAFETY: status is the documented MEMORYSTATUSEX layout, with its size initialized.
    (unsafe { GlobalMemoryStatusEx(&mut status) } != 0)
        .then_some(status.available_physical.min(status.available_pagefile))
}

#[cfg(target_os = "macos")]
fn available_bytes() -> Option<u64> {
    macos::available_bytes()
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn available_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_budget_bounds_cpu_ram_and_unknown_hosts() {
        assert_eq!(worker_limit(32, Some(512 * MIB)), 0);
        assert_eq!(worker_limit(32, Some(576 * MIB)), 8);
        assert_eq!(worker_limit(12, Some(8 * 1024 * MIB)), 12);
        assert_eq!(worker_limit(500, Some(u64::MAX)), MAX_WORKERS);
        assert_eq!(worker_limit(32, None), 1);
    }
}
