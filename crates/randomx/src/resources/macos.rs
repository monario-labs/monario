//! macOS live memory sampling through Mach host statistics.
//!
//! The reported value is the kernel's live free-page count. It is deliberately
//! conservative: speculative pages are already included in `free_count`, and
//! inactive, purgeable and compressed pages are not added back.

#[cfg(target_os = "macos")]
use std::ffi::{c_char, c_int, c_void};

/// Mach `host_statistics64` flavor for `vm_statistics64_data_t`.
#[cfg(target_os = "macos")]
const HOST_VM_INFO64: c_int = 4;
/// Mach `KERN_SUCCESS`.
#[cfg(target_os = "macos")]
const KERN_SUCCESS: c_int = 0;

#[cfg(target_os = "macos")]
type MachPort = u32;
#[cfg(target_os = "macos")]
type KernReturn = c_int;
#[cfg(target_os = "macos")]
type VmSize = usize;

/// Mirrors the `HOST_VM_INFO64` rev1 `vm_statistics64_data_t` layout (38 32-bit
/// words) so the kernel writes into an exactly sized buffer. Only `free_count`
/// is read.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Default)]
struct VmStatistics64 {
    free_count: u32,
    active_count: u32,
    inactive_count: u32,
    wire_count: u32,
    zero_fill_count: u64,
    reactivations: u64,
    pageins: u64,
    pageouts: u64,
    faults: u64,
    cow_faults: u64,
    lookups: u64,
    hits: u64,
    purges: u64,
    purgeable_count: u32,
    speculative_count: u32,
    decompressions: u64,
    compressions: u64,
    swapins: u64,
    swapouts: u64,
    compressor_page_count: u32,
    throttled_count: u32,
    external_page_count: u32,
    internal_page_count: u32,
    total_uncompressed_pages_in_compressor: u64,
}

/// `vm_statistics64_data_t` is declared with 8-byte alignment on Darwin.
#[cfg(target_os = "macos")]
#[repr(C, align(8))]
#[derive(Default)]
struct VmStatistics64Buffer(VmStatistics64);

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_host_self() -> MachPort;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;
    fn host_page_size(host: MachPort, page_size: *mut VmSize) -> KernReturn;
    fn host_statistics64(
        host: MachPort,
        flavor: c_int,
        info: *mut c_int,
        count: *mut u32,
    ) -> KernReturn;
    fn sysctlbyname(
        name: *const c_char,
        old: *mut c_void,
        old_len: *mut usize,
        new: *const c_void,
        new_len: usize,
    ) -> c_int;
    static mach_task_self_: MachPort;
}

/// Releases the send right returned by `mach_host_self` on every exit path.
#[cfg(target_os = "macos")]
struct HostPort(MachPort);

#[cfg(target_os = "macos")]
impl Drop for HostPort {
    fn drop(&mut self) {
        // SAFETY: `mach_task_self_` is the task port supplied by libSystem and
        // `self.0` is the send right returned once by `mach_host_self`, so it
        // is deallocated exactly once here.
        unsafe {
            mach_port_deallocate(mach_task_self_, self.0);
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn available_bytes() -> Option<u64> {
    // SAFETY: `mach_host_self` takes no arguments and returns a new send right
    // (or MACH_PORT_NULL), which `HostPort` deallocates exactly once.
    let host = unsafe { mach_host_self() };
    if host == 0 {
        return None;
    }
    let host = HostPort(host);

    let mut page_size: VmSize = 0;
    // SAFETY: `host` is a valid host port and `page_size` points to writable
    // storage for the single `vm_size_t` the kernel writes.
    let page_status = unsafe { host_page_size(host.0, &mut page_size) };
    if page_status != KERN_SUCCESS || page_size == 0 {
        return None;
    }
    let page_size = u64::try_from(page_size).ok()?;

    let mut buffer = VmStatistics64Buffer::default();
    let expected =
        u32::try_from(std::mem::size_of::<VmStatistics64>() / std::mem::size_of::<u32>()).ok()?;
    let mut count = expected;
    // SAFETY: `buffer` is an 8-byte-aligned, exactly sized 38-word
    // `HOST_VM_INFO64` rev1 structure, which modern XNU accepts at the requested
    // size; `count` is that size in 32-bit words and is updated by the kernel.
    // Both out-pointers are valid for the call.
    let stats_status = unsafe {
        host_statistics64(
            host.0,
            HOST_VM_INFO64,
            (&mut buffer.0 as *mut VmStatistics64).cast::<c_int>(),
            &mut count,
        )
    };
    if stats_status != KERN_SUCCESS || count != expected {
        return None;
    }

    let physical = physical_memory()?;
    bound_free_bytes(page_size, u64::from(buffer.0.free_count), physical)
}

#[cfg(target_os = "macos")]
fn physical_memory() -> Option<u64> {
    let mut bytes = 0u64;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: `hw.memsize` is a NUL-terminated key; `bytes` is writable for
    // `len` bytes and a null input pointer requests a read-only query.
    let status = unsafe {
        sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&mut bytes as *mut u64).cast::<c_void>(),
            &mut len,
            std::ptr::null(),
            0,
        )
    };
    (status == 0 && len == std::mem::size_of::<u64>() && bytes > 0).then_some(bytes)
}

/// Converts a kernel free-page count to bytes and bounds it by physical RAM.
///
/// Returns `None` for a sample that cannot describe usable memory: a zero page
/// size, zero physical memory, or a byte count that overflows `u64`.
fn bound_free_bytes(page_size: u64, free_pages: u64, physical_bytes: u64) -> Option<u64> {
    if page_size == 0 || physical_bytes == 0 {
        return None;
    }
    let free = free_pages.checked_mul(page_size)?;
    Some(free.min(physical_bytes))
}

/// Live sampling only exists on Darwin; this keeps the file buildable and its
/// arithmetic tests runnable elsewhere.
#[cfg(not(target_os = "macos"))]
pub(super) fn available_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_free_pages_by_physical_memory() {
        assert_eq!(bound_free_bytes(4096, 3, 16 * 4096), Some(3 * 4096));
        assert_eq!(bound_free_bytes(4096, 24, 16 * 4096), Some(16 * 4096));
        assert_eq!(bound_free_bytes(16 * 1024, 4, 48 * 1024), Some(48 * 1024));
    }

    #[test]
    fn rejects_unusable_samples() {
        assert_eq!(bound_free_bytes(0, 10, 4096), None);
        assert_eq!(bound_free_bytes(4096, 10, 0), None);
        assert_eq!(bound_free_bytes(1u64 << 32, u64::MAX, u64::MAX), None);
    }

    #[test]
    fn zero_free_pages_is_a_valid_conservative_sample() {
        assert_eq!(bound_free_bytes(4096, 0, 4096), Some(0));
    }

    /// Native smoke test: the production Mach probe must return a sample that is
    /// bounded by this host's physical memory. Zero free pages is a valid
    /// reading under memory pressure, so only the upper bound is asserted.
    #[cfg(target_os = "macos")]
    #[test]
    fn live_sample_is_bounded_by_physical_memory() {
        let physical = physical_memory().expect("hw.memsize must be readable on macOS");
        let sample = available_bytes().expect("HOST_VM_INFO64 sampling must succeed on macOS");
        assert!(
            sample <= physical,
            "live free-memory sample {sample} exceeds physical memory {physical}"
        );
    }
}
