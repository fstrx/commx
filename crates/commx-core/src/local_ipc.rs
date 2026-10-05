//! The local control channel between `commx` and `commxd`, restricted to the
//! current OS user.
//!
//! - Unix: a 0600 unix socket in the private data dir, plus a peer-UID check.
//! - Windows: a named pipe whose DACL grants access only to the current user,
//!   remote clients rejected, first-instance only. The client checks that the
//!   pipe server runs as the same user, so another account can't squat the
//!   name and impersonate the daemon.

use std::io;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};

pub type Reader = Box<dyn AsyncRead + Unpin + Send>;
pub type Writer = Box<dyn AsyncWrite + Unpin + Send>;

/// Default endpoint for a data dir: a socket path or a pipe name.
pub fn default_endpoint(data_dir: &Path) -> String {
    #[cfg(unix)]
    {
        data_dir.join("commxd.sock").to_string_lossy().into_owned()
    }
    #[cfg(windows)]
    {
        // One pipe per data dir, so several daemons can coexist.
        let tag = blake3::hash(data_dir.to_string_lossy().as_bytes());
        format!(r"\\.\pipe\commx-{}", &tag.to_hex()[..16])
    }
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use tokio::net::{UnixListener, UnixStream};

    pub async fn connect(endpoint: &str) -> io::Result<(Reader, Writer)> {
        let (r, w) = UnixStream::connect(endpoint).await?.into_split();
        Ok((Box::new(r), Box::new(w)))
    }

    pub struct Listener {
        inner: UnixListener,
        path: std::path::PathBuf,
    }

    impl Listener {
        pub fn bind(endpoint: &str) -> io::Result<Self> {
            let path = Path::new(endpoint);
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                // Only ever delete a stale socket, never some other file.
                if !meta.file_type().is_socket() {
                    return Err(io::Error::other(format!("{endpoint} exists and is not a socket")));
                }
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return Err(io::Error::new(io::ErrorKind::AddrInUse, "commxd already running"));
                }
                std::fs::remove_file(path)?;
            }
            let inner = UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self { inner, path: path.to_path_buf() })
        }

        /// Next client of the same user (others are dropped silently).
        pub async fn accept(&mut self) -> io::Result<(Reader, Writer)> {
            let uid = unsafe { libc::getuid() };
            loop {
                let (s, _) = self.inner.accept().await?;
                if s.peer_cred().map(|c| c.uid() == uid).unwrap_or(false) {
                    let (r, w) = s.into_split();
                    return Ok((Box::new(r), Box::new(w)));
                }
            }
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{EqualSid, GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// TOKEN_USER buffer of a process (its owning account's SID inside).
    fn process_user(process: HANDLE) -> io::Result<Vec<u8>> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, len, &mut len);
            CloseHandle(token);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(buf)
        }
    }

    fn sid_of(token_user: &[u8]) -> *mut c_void {
        unsafe { (*(token_user.as_ptr() as *const TOKEN_USER)).User.Sid }
    }

    /// DACL: full access for the current user only, nobody else.
    fn user_only_attributes() -> io::Result<(SECURITY_ATTRIBUTES, *mut c_void)> {
        unsafe {
            let me = process_user(GetCurrentProcess())?;
            let mut sid_str: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(sid_of(&me), &mut sid_str) == 0 {
                return Err(io::Error::last_os_error());
            }
            let len = (0..).take_while(|&i| *sid_str.add(i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, len));
            LocalFree(sid_str as *mut c_void);
            let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})").encode_utf16().chain(Some(0)).collect();
            let mut sd: *mut c_void = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            Ok((attrs, sd))
        }
    }

    fn create(name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let (mut attrs, sd) = user_only_attributes()?;
        let res = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, &mut attrs as *mut _ as *mut c_void)
        };
        unsafe { LocalFree(sd) };
        res
    }

    pub async fn connect(endpoint: &str) -> io::Result<(Reader, Writer)> {
        let pipe = ClientOptions::new().open(endpoint)?;
        // Refuse a pipe served by anyone but us (name squatting).
        unsafe {
            use std::os::windows::io::AsRawHandle;
            let mut pid = 0u32;
            if GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) == 0 {
                return Err(io::Error::last_os_error());
            }
            let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if proc.is_null() {
                return Err(io::Error::last_os_error());
            }
            let theirs = process_user(proc);
            CloseHandle(proc);
            let mine = process_user(GetCurrentProcess())?;
            if EqualSid(sid_of(&theirs?), sid_of(&mine)) == 0 {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "pipe is owned by another user"));
            }
        }
        let (r, w) = tokio::io::split(pipe);
        Ok((Box::new(r), Box::new(w)))
    }

    pub struct Listener {
        name: String,
        next: NamedPipeServer,
    }

    impl Listener {
        pub fn bind(endpoint: &str) -> io::Result<Self> {
            let next = create(endpoint, true).map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    io::Error::new(io::ErrorKind::AddrInUse, "commxd already running (or pipe name taken)")
                } else {
                    e
                }
            })?;
            Ok(Self { name: endpoint.to_string(), next })
        }

        /// The DACL already limits clients to the current user.
        pub async fn accept(&mut self) -> io::Result<(Reader, Writer)> {
            self.next.connect().await?;
            let fresh = create(&self.name, false)?;
            let connected = std::mem::replace(&mut self.next, fresh);
            let (r, w) = tokio::io::split(connected);
            Ok((Box::new(r), Box::new(w)))
        }
    }
}

pub use imp::{connect, Listener};
