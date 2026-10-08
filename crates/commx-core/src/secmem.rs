//! Memory hygiene: make a RAM dump / memory scan of commx useless for
//! recovering messages or keys.
//!
//! - [`ZeroizingAlloc`]: global allocator that wipes every block on free, so
//!   plaintext never lingers in freed heap memory.
//! - [`Locked`]: page-aligned, page-locked (no swap), dump-excluded, wiped-on-drop
//!   storage for keys.
//! - [`SealedLog`]: message history kept encrypted in RAM under a locked key and
//!   decrypted only for the moment it's needed.
//! - [`ZLines`]: line reader whose buffers are wiped, replacing `BufReader`.
//! - [`harden_process`]: no core dumps, no debugger attach where the OS allows.
//!
//! Limits: live plaintext exists while it's being shown or sent, and anything
//! with root/kernel access can read the locked keys. This raises the bar from
//! "grep the dump" to "reverse the process while it runs".

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::VecDeque;
use std::ptr::NonNull;
use std::sync::atomic::{compiler_fence, Ordering};

use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{aead_decrypt, aead_encrypt};

/// Overwrite `len` bytes at `ptr` with zeros in a way the optimizer can't drop.
///
/// # Safety
/// `ptr..ptr+len` must be valid for writes.
unsafe fn wipe(ptr: *mut u8, len: usize) {
    let words = len / std::mem::size_of::<usize>();
    let wp = ptr as *mut usize;
    for i in 0..words {
        std::ptr::write_volatile(wp.add(i), 0);
    }
    for i in words * std::mem::size_of::<usize>()..len {
        std::ptr::write_volatile(ptr.add(i), 0);
    }
    compiler_fence(Ordering::SeqCst);
}

/// Wipes every heap block before returning it to the system allocator.
/// `realloc` uses the trait's default (alloc + copy + dealloc), so the old
/// block of a growing `Vec`/`String` is wiped too.
pub struct ZeroizingAlloc;

unsafe impl GlobalAlloc for ZeroizingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        wipe(ptr, layout.size());
        System.dealloc(ptr, layout)
    }
}

fn page_size() -> usize {
    #[cfg(unix)]
    {
        (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).max(4096) as usize
    }
    #[cfg(windows)]
    {
        let mut info: windows_sys::Win32::System::SystemInformation::SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { windows_sys::Win32::System::SystemInformation::GetSystemInfo(&mut info) };
        (info.dwPageSize as usize).max(4096)
    }
    // WebAssembly: no paging or locking; keep allocations small.
    #[cfg(not(any(unix, windows)))]
    {
        64
    }
}

/// Pin pages in RAM and keep them out of core dumps. Best effort: failure
/// (e.g. RLIMIT_MEMLOCK) leaves the data wiped-on-drop but swappable.
#[cfg_attr(not(any(unix, windows)), allow(unused_variables))]
fn lock_pages(ptr: *mut u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len);
        #[cfg(target_os = "linux")]
        libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(ptr as *const core::ffi::c_void, len);
    }
}

#[cfg_attr(not(any(unix, windows)), allow(unused_variables))]
fn unlock_pages(ptr: *mut u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *const core::ffi::c_void, len);
    }
}

/// N secret bytes on their own locked page(s). Each value gets whole pages so
/// unlocking one can never unlock another.
pub struct Locked<const N: usize> {
    ptr: NonNull<u8>,
    layout: Layout,
}

unsafe impl<const N: usize> Send for Locked<N> {}
unsafe impl<const N: usize> Sync for Locked<N> {}

impl<const N: usize> Locked<N> {
    pub fn zeroed() -> Self {
        let page = page_size();
        let layout = Layout::from_size_align(N.div_ceil(page).max(1) * page, page).expect("layout");
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));
        lock_pages(ptr.as_ptr(), layout.size());
        Self { ptr, layout }
    }

    pub fn random() -> Self {
        let mut k = Self::zeroed();
        OsRng.fill_bytes(k.bytes_mut());
        k
    }

    pub fn from_bytes(b: &[u8; N]) -> Self {
        let mut k = Self::zeroed();
        k.bytes_mut().copy_from_slice(b);
        k
    }

    pub fn bytes(&self) -> &[u8; N] {
        unsafe { &*(self.ptr.as_ptr() as *const [u8; N]) }
    }

    pub fn bytes_mut(&mut self) -> &mut [u8; N] {
        unsafe { &mut *(self.ptr.as_ptr() as *mut [u8; N]) }
    }
}

impl<const N: usize> Clone for Locked<N> {
    fn clone(&self) -> Self {
        Self::from_bytes(self.bytes())
    }
}

impl<const N: usize> Drop for Locked<N> {
    fn drop(&mut self) {
        unsafe {
            wipe(self.ptr.as_ptr(), self.layout.size());
            unlock_pages(self.ptr.as_ptr(), self.layout.size());
            std::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// Append-only history kept encrypted in RAM. A memory scan finds only
/// ciphertext; dropping it (a nuke) wipes the key and makes the rest noise.
pub struct SealedLog {
    key: Locked<32>,
    items: VecDeque<([u8; 24], Vec<u8>)>,
    cap: usize,
}

impl SealedLog {
    pub fn new(cap: usize) -> Self {
        Self { key: Locked::random(), items: VecDeque::new(), cap }
    }

    pub fn push<T: Serialize>(&mut self, item: &T) {
        let plain = Zeroizing::new(postcard::to_allocvec(item).expect("serialize log item"));
        let sealed = aead_encrypt(self.key.bytes(), &plain, b"commx-log").expect("seal log item");
        self.items.push_back(sealed);
        while self.items.len() > self.cap {
            self.items.pop_front();
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Decrypt items `skip_from_end..` counting back from the newest, newest last.
    /// Callers should drop the result as soon as it's used.
    pub fn tail<T: DeserializeOwned>(&self, max: usize, skip_from_end: usize) -> Vec<T> {
        let end = self.items.len().saturating_sub(skip_from_end);
        let start = end.saturating_sub(max);
        self.items
            .range(start..end)
            .filter_map(|(n, ct)| {
                let plain = aead_decrypt(self.key.bytes(), n, ct, b"commx-log").ok()?;
                postcard::from_bytes(&plain).ok()
            })
            .collect()
    }

    pub fn all<T: DeserializeOwned>(&self) -> Vec<T> {
        self.tail(usize::MAX, 0)
    }
}

/// Newline-delimited reader that wipes its buffers (unlike `BufReader`, which
/// keeps the last few KiB of plaintext around indefinitely).
pub struct ZLines<R> {
    inner: R,
    buf: Zeroizing<Vec<u8>>,
    max: usize,
}

impl<R: tokio::io::AsyncRead + Unpin> ZLines<R> {
    pub fn new(inner: R, max: usize) -> Self {
        Self { inner, buf: Zeroizing::new(Vec::new()), max }
    }

    pub async fn next_line(&mut self) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
        use tokio::io::AsyncReadExt;
        loop {
            if let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
                let line = Zeroizing::new(self.buf[..i].to_vec());
                let len = self.buf.len();
                self.buf.copy_within(i + 1.., 0);
                let rest = len - (i + 1);
                self.buf[rest..].zeroize();
                self.buf.truncate(rest);
                return Ok(Some(line));
            }
            if self.buf.len() > self.max {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
            }
            let mut chunk = Zeroizing::new([0u8; 4096]);
            let n = self.inner.read(&mut chunk[..]).await?;
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Process-level hardening. Call first thing in `main`.
pub fn harden_process() {
    #[cfg(unix)]
    unsafe {
        // Core dumps would contain keys and plaintext.
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        // Linux: no ptrace/proc-mem access from same-uid processes, no dumps.
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        // macOS release builds: refuse debugger attach.
        #[cfg(all(target_os = "macos", not(debug_assertions)))]
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
        };
        // No Windows Error Reporting crash dialog / dump on fault.
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_roundtrip() {
        let k = Locked::<32>::random();
        let c = k.clone();
        assert_eq!(k.bytes(), c.bytes());
        assert_ne!(k.bytes(), &[0u8; 32]);
    }

    #[test]
    fn sealed_log_stores_ciphertext_only() {
        let mut log = SealedLog::new(3);
        for i in 0..5 {
            log.push(&format!("secret message {i}"));
        }
        assert_eq!(log.len(), 3);
        let all: Vec<String> = log.all();
        assert_eq!(all, vec!["secret message 2", "secret message 3", "secret message 4"]);
        let tail: Vec<String> = log.tail(1, 1);
        assert_eq!(tail, vec!["secret message 3"]);
        for (_, ct) in &log.items {
            assert!(!ct.windows(6).any(|w| w == b"secret"));
        }
    }

    #[test]
    fn wipe_zeroes() {
        let mut v = vec![0xAAu8; 37];
        unsafe { wipe(v.as_mut_ptr(), v.len()) };
        assert!(v.iter().all(|b| *b == 0));
    }

    #[tokio::test]
    async fn zlines_splits() {
        let data: &[u8] = b"one\ntwo\npartial";
        let mut z = ZLines::new(data, 1024);
        assert_eq!(&**z.next_line().await.unwrap().unwrap(), b"one");
        assert_eq!(&**z.next_line().await.unwrap().unwrap(), b"two");
        assert!(z.next_line().await.unwrap().is_none());
    }
}
