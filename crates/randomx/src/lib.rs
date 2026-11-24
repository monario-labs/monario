//! Pinned RandomX v2.0.1 light-mode verifier. No mining loop or dataset allocation.
//! Initialized caches can be shared. Virtual machines remain thread-local.
use std::{ffi::c_void, marker::PhantomData, ptr::NonNull, rc::Rc, sync::Arc};

mod resources;
pub use resources::{MAX_WORKERS, mining_worker_limit};

const V2: u32 = 128;
/// Execution choices with identical consensus results; no caller-controlled flags.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Interpreter,
    SecureJit,
}
/// Vendored upstream revision, algorithm version is additionally forced by V2.
pub const UPSTREAM_REVISION: &str = "aaafe71322df6602c21a5c72937ac284724ae561";
/// Maximum accepted hash preimage size; a resource bound, not a block codec.
pub const MAX_INPUT_BYTES: usize = 4096;

unsafe extern "C" {
    fn randomx_alloc_cache(flags: u32) -> *mut c_void;
    fn randomx_init_cache(cache: *mut c_void, key: *const c_void, size: usize);
    fn randomx_release_cache(cache: *mut c_void);
    fn randomx_create_vm(flags: u32, cache: *mut c_void, dataset: *mut c_void) -> *mut c_void;
    fn randomx_destroy_vm(vm: *mut c_void);
    fn randomx_calculate_hash(
        vm: *mut c_void,
        input: *const c_void,
        size: usize,
        output: *mut c_void,
    );
}

/// Construction or verification-input failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidSeed,
    InputTooLarge,
    AllocationFailed,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RandomX: {self:?}")
    }
}
impl std::error::Error for Error {}

struct Cache {
    raw: NonNull<c_void>,
    seed: Vec<u8>,
}

// SAFETY: initialization completes before publishing Cache. This wrapper never invokes
// randomx_init_cache again or exposes the pointer. The vendored light VMs only read
// the cache's memory and metadata and allocate their own scratchpad and JIT state.
unsafe impl Send for Cache {}
// SAFETY: the same immutable-cache invariant applies to concurrent light VMs.
unsafe impl Sync for Cache {}

impl Drop for Cache {
    fn drop(&mut self) {
        // SAFETY: the last Arc was released after every associated VM was destroyed.
        unsafe { randomx_release_cache(self.raw.as_ptr()) }
    }
}

/// An immutable, initialized light cache for one seed. Initialization allocates 256 MiB.
#[derive(Clone)]
pub struct SharedCache(Arc<Cache>);

impl SharedCache {
    pub fn new(seed: &[u8]) -> Result<Self, Error> {
        if seed.is_empty() || seed.len() > 64 {
            return Err(Error::InvalidSeed);
        }
        // SAFETY: flags 0 select the default non-JIT, light cache allocation.
        let raw = NonNull::new(unsafe { randomx_alloc_cache(0) }).ok_or(Error::AllocationFailed)?;
        // SAFETY: the cache is exclusively owned and the seed is live during initialization.
        unsafe { randomx_init_cache(raw.as_ptr(), seed.as_ptr().cast(), seed.len()) };
        Ok(Self(Arc::new(Cache {
            raw,
            seed: seed.to_vec(),
        })))
    }

    pub fn seed(&self) -> &[u8] {
        &self.0.seed
    }

    /// Create a VM on the thread where it will run.
    pub fn verifier(&self, mode: Mode) -> Result<Verifier, Error> {
        let flags = match mode {
            Mode::Interpreter => V2,
            Mode::SecureJit => V2 | 8 | 16,
        };
        // SAFETY: the initialized cache outlives the VM; light mode has no dataset.
        let vm = NonNull::new(unsafe {
            randomx_create_vm(flags, self.0.raw.as_ptr(), std::ptr::null_mut())
        })
        .ok_or(Error::AllocationFailed)?;
        Ok(Verifier {
            vm,
            cache: self.clone(),
            _thread_local: PhantomData,
        })
    }
}

/// Thread-local, reusable verifier with an immutable seed identity.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<monario_randomx::Verifier>();
/// ```
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<monario_randomx::Verifier>();
/// ```
pub struct Verifier {
    vm: NonNull<c_void>,
    cache: SharedCache,
    _thread_local: PhantomData<Rc<()>>,
}
impl Verifier {
    /// Construct a software-AES interpreter. Seed length is bounded before allocation.
    pub fn new(seed: &[u8]) -> Result<Self, Error> {
        Self::with_mode(seed, Mode::Interpreter)
    }
    /// Select the interpreter or W^X JIT. Neither mode allocates a full dataset.
    pub fn with_mode(seed: &[u8], mode: Mode) -> Result<Self, Error> {
        SharedCache::new(seed)?.verifier(mode)
    }
    /// The seed this cache actually contains; callers must compare branch seed identities.
    pub fn seed(&self) -> &[u8] {
        self.cache.seed()
    }
    /// Calculate one bounded v2 digest. This never searches nonces.
    pub fn hash(&mut self, input: &[u8]) -> Result<[u8; 32], Error> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(Error::InputTooLarge);
        }
        let mut output = [0; 32];
        // SAFETY: exclusive VM access; input is live and output has the required 32 bytes.
        unsafe {
            randomx_calculate_hash(
                self.vm.as_ptr(),
                input.as_ptr().cast(),
                input.len(),
                output.as_mut_ptr().cast(),
            );
        }
        Ok(output)
    }
}
impl Drop for Verifier {
    fn drop(&mut self) {
        // SAFETY: unique VM owner; Rust drops the backing cache after this method.
        unsafe {
            randomx_destroy_vm(self.vm.as_ptr());
        }
    }
}
