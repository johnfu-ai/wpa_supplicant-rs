//! `AF_PACKET / SOCK_RAW` `NetworkIo` implementation for Linux.
//!
//! Implements: #128 — Phase 07 prerequisite for the FreeRADIUS interop harness
//! (`docs/TODO.md` P3.1). Replaces the [`crate::NoopNetworkIo`] stub on the prod
//! path when the `raw-socket` feature is enabled.
//!
//! Architecture: ARC-C-WPA-005 (#85), ADR-WS-001 (#73), ADR-FF-006 (#78).
//!
//! ## Capability requirements
//!
//! Opening an `AF_PACKET` socket requires `CAP_NET_RAW`. The binary surfaces a
//! clear `tracing::error!` with a non-zero exit when the capability is missing
//! rather than letting the bind call fail with a bare `EPERM`.
//!
//! ## Unsafe surface
//!
//! All FFI calls into `libc` are isolated to this module. Every `unsafe` block
//! carries a `// SAFETY:` comment per the workspace non-negotiable
//! (see `CLAUDE.md` §8). The owned-FD discipline is encapsulated in
//! [`OwnedFd`] so callers never see a raw descriptor.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

#![cfg(feature = "raw-socket")]

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::raw::c_int;

use anyhow::{anyhow, Context, Result};

use crate::network_io::NetworkIo;

/// EtherType for EAPOL frames per IEEE 802.1X-2020 §11.1.4.
const ETH_P_PAE: u16 = 0x888E;
/// Length of a standard Ethernet II header (dest + src + ethertype).
const ETH_HDR_LEN: usize = 14;
/// Maximum Ethernet payload (MTU 1500) + header.
const RX_BUF_LEN: usize = 1514;

/// RAII wrapper around a raw file descriptor.
///
/// Closes the FD on drop. Owning this struct is the in-Rust authority that the
/// FD is live; once dropped, the kernel descriptor is gone and any further use
/// is a logic bug, not a memory-safety violation (the kernel rejects with
/// `EBADF`).
struct OwnedFd(c_int);

impl OwnedFd {
    fn raw(&self) -> c_int {
        self.0
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by `socket(2)` (or an equivalent
        // syscall) earlier in this module and has not been closed elsewhere —
        // `OwnedFd` is the sole owner. `close(2)` on a valid descriptor is
        // always safe; the worst case is `EBADF`, which we ignore on drop.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// `NetworkIo` backed by a Linux `AF_PACKET / SOCK_RAW` socket.
///
/// Per the IEEE 802.1X-2020 §11 Uncontrolled Port: frames are sent and
/// received with EtherType `0x888E` and bypass any MACsec confidentiality
/// transform.
pub struct RawSocketNetworkIo {
    fd: OwnedFd,
    if_index: c_int,
    mac: [u8; 6],
    interface: String,
}

impl RawSocketNetworkIo {
    /// Bind a non-blocking `AF_PACKET / SOCK_RAW` socket to `interface`.
    ///
    /// Returns:
    /// * `Ok(Self)` on success.
    /// * `Err(_)` wrapping the underlying `io::Error` on failure. A missing
    ///   `CAP_NET_RAW` capability surfaces as `Err(EPERM)` here; the binary
    ///   entry point converts that to a clear log line + non-zero exit.
    pub fn bind(interface: &str) -> Result<Self> {
        let fd = socket_raw_packet()
            .with_context(|| format!("opening AF_PACKET socket for {interface}"))?;
        set_nonblocking(&fd).context("setting socket non-blocking")?;
        let if_index = lookup_if_index(interface)
            .with_context(|| format!("resolving interface index for {interface}"))?;
        let mac = lookup_mac(interface)
            .with_context(|| format!("reading MAC address for {interface}"))?;
        bind_to_interface(&fd, if_index).context("binding socket to interface")?;
        Ok(Self {
            fd,
            if_index,
            mac,
            interface: interface.to_string(),
        })
    }

    /// Read the cached interface name (useful for diagnostics).
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

impl NetworkIo for RawSocketNetworkIo {
    fn send_eapol(&self, dest: [u8; 6], frame: &[u8]) -> Result<()> {
        // Prepend the Ethernet II header so callers only have to pass the
        // EAPOL payload starting at the version octet. This matches the
        // contract used by `MockNetworkIo` and `NoopNetworkIo`.
        let mut buf = Vec::with_capacity(ETH_HDR_LEN + frame.len());
        buf.extend_from_slice(&dest);
        buf.extend_from_slice(&self.mac);
        buf.extend_from_slice(&ETH_P_PAE.to_be_bytes());
        buf.extend_from_slice(frame);

        // SAFETY: `sockaddr_ll` is a POD C struct of integral fields with
        // no padding invariants we violate; all-zero is a valid initial
        // state before we fill in the family / protocol / index / halen /
        // addr fields below.
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as libc::sa_family_t;
        addr.sll_protocol = ETH_P_PAE.to_be();
        addr.sll_ifindex = self.if_index;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&dest);

        // SAFETY: `self.fd.raw()` is a live `AF_PACKET / SOCK_RAW` socket
        // owned by `self.fd`; `buf` is a contiguous, initialized byte slice
        // valid for `buf.len()` bytes; `addr` is a fully-initialized
        // `sockaddr_ll` whose lifetime exceeds the call.
        let sent = unsafe {
            libc::sendto(
                self.fd.raw(),
                buf.as_ptr() as *const _,
                buf.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error()).context("sendto on AF_PACKET socket");
        }
        if (sent as usize) != buf.len() {
            return Err(anyhow!(
                "short send: {sent} of {} bytes on {}",
                buf.len(),
                self.interface
            ));
        }
        tracing::trace!(
            ?dest,
            len = buf.len(),
            interface = %self.interface,
            "raw-socket: sent EAPOL frame"
        );
        Ok(())
    }

    fn recv_eapol(&self) -> Result<Option<Vec<u8>>> {
        let mut buf = [0u8; RX_BUF_LEN];
        // SAFETY: `self.fd.raw()` is a live socket owned by `self.fd`; `buf`
        // is a stack-allocated, fully-initialized array of `RX_BUF_LEN`
        // bytes valid for the call; the kernel writes at most `buf.len()`
        // bytes and returns the count.
        let n = unsafe { libc::recv(self.fd.raw(), buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            // On Linux `EAGAIN` and `EWOULDBLOCK` are the same constant, so we
            // only need to match one — the other arm would be unreachable.
            match err.raw_os_error() {
                Some(libc::EAGAIN) => return Ok(None),
                _ => return Err(err).context("recv on AF_PACKET socket"),
            }
        }
        let n = n as usize;
        if n < ETH_HDR_LEN {
            // Frame too small to contain an Ethernet header — discard.
            tracing::trace!(len = n, "raw-socket: discarded undersized frame");
            return Ok(None);
        }
        // Strip the L2 header — callers expect the EAPOL payload only,
        // matching the `MockNetworkIo` / `NoopNetworkIo` contract.
        let payload = buf[ETH_HDR_LEN..n].to_vec();
        Ok(Some(payload))
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        match read_link_state(&self.interface) {
            Ok(up) => up,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    interface = %self.interface,
                    "raw-socket: failed to read link state; reporting down"
                );
                false
            }
        }
    }
}

// --- Low-level FFI helpers --------------------------------------------------
//
// Each helper isolates one `unsafe` block to keep the `// SAFETY:` rationale
// next to the syscall it justifies.

fn socket_raw_packet() -> Result<OwnedFd> {
    // SAFETY: `socket(2)` takes three `c_int` arguments and returns a `c_int`
    // (positive FD on success, -1 on failure). All inputs are constants from
    // `libc` and require no preconditions beyond `CAP_NET_RAW`, which the
    // kernel checks. `htons(ETH_P_PAE)` produces a well-defined `u16`.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_PAE.to_be() as c_int) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(OwnedFd(fd))
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    // SAFETY: `fd.raw()` is a live FD owned by `fd`; `fcntl(F_GETFL)` has no
    // memory-safety preconditions beyond a valid descriptor.
    let flags = unsafe { libc::fcntl(fd.raw(), libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: same as above; `O_NONBLOCK` is a constant flag bit.
    let rc = unsafe { libc::fcntl(fd.raw(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn lookup_if_index(interface: &str) -> Result<c_int> {
    let cname = CString::new(interface).context("interface name contains NUL byte")?;
    // SAFETY: `cname.as_ptr()` returns a NUL-terminated C string valid for
    // the duration of the call (it borrows `cname`, which outlives the call).
    // `if_nametoindex` reads only up to the NUL terminator.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("if_nametoindex({interface})"));
    }
    Ok(idx as c_int)
}

fn bind_to_interface(fd: &OwnedFd, if_index: c_int) -> Result<()> {
    // SAFETY: `mem::zeroed()` is sound for `sockaddr_ll` — it is a POD
    // C struct of integral fields, and all-zero is a valid initial state
    // before we fill in the protocol / family / index.
    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as libc::sa_family_t;
    addr.sll_protocol = ETH_P_PAE.to_be();
    addr.sll_ifindex = if_index;

    // SAFETY: `fd.raw()` is a live socket FD owned by `fd`; `&addr` is a
    // fully-initialized `sockaddr_ll` valid for the duration of the call;
    // the size matches `sizeof(sockaddr_ll)`.
    let rc = unsafe {
        libc::bind(
            fd.raw(),
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Read the MAC address of `interface` via `SIOCGIFHWADDR`.
fn lookup_mac(interface: &str) -> Result<[u8; 6]> {
    // Open a throwaway control socket — `SIOCGIFHWADDR` works on any
    // domain-socket FD and we don't want to touch the AF_PACKET socket here.
    // SAFETY: `socket(2)` with `AF_INET / SOCK_DGRAM / 0` is the canonical
    // ioctl-control socket recipe and has no preconditions.
    let ctl = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if ctl < 0 {
        return Err(io::Error::last_os_error()).context("open ioctl control socket");
    }
    let ctl = OwnedFd(ctl);

    let cname = CString::new(interface).context("interface name contains NUL byte")?;
    // SAFETY: `mem::zeroed()` is sound for `ifreq` — POD with no padding
    // invariants we violate.
    let mut req: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = cname.as_bytes_with_nul();
    if name_bytes.len() > req.ifr_name.len() {
        return Err(anyhow!("interface name '{interface}' too long for ifreq"));
    }
    for (dst, &src) in req.ifr_name.iter_mut().zip(name_bytes.iter()) {
        *dst = src as libc::c_char;
    }

    // SAFETY: `ctl.raw()` is a live control socket; `&mut req` is a fully
    // initialized `ifreq` with `ifr_name` populated; `SIOCGIFHWADDR` writes
    // into the `ifr_hwaddr` union variant which `ifreq` guarantees is
    // representable.
    let rc = unsafe { libc::ioctl(ctl.raw(), libc::SIOCGIFHWADDR, &mut req) };
    if rc < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("SIOCGIFHWADDR({interface})"));
    }
    // SAFETY: after a successful `SIOCGIFHWADDR`, the kernel guarantees the
    // `ifr_hwaddr.sa_data` field is populated with at least 6 bytes of MAC.
    let sa = unsafe { req.ifr_ifru.ifru_hwaddr };
    let mut mac = [0u8; 6];
    for (i, slot) in mac.iter_mut().enumerate() {
        *slot = sa.sa_data[i] as u8;
    }
    Ok(mac)
}

/// Read the link state of `interface` via `SIOCGIFFLAGS`.
///
/// Returns `true` when both `IFF_UP` and `IFF_RUNNING` are set.
fn read_link_state(interface: &str) -> Result<bool> {
    // SAFETY: see `lookup_mac` — same idiom.
    let ctl = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if ctl < 0 {
        return Err(io::Error::last_os_error()).context("open ioctl control socket");
    }
    let ctl = OwnedFd(ctl);

    let cname = CString::new(interface).context("interface name contains NUL byte")?;
    // SAFETY: see `lookup_mac`.
    let mut req: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = cname.as_bytes_with_nul();
    if name_bytes.len() > req.ifr_name.len() {
        return Err(anyhow!("interface name '{interface}' too long for ifreq"));
    }
    for (dst, &src) in req.ifr_name.iter_mut().zip(name_bytes.iter()) {
        *dst = src as libc::c_char;
    }

    // SAFETY: see `lookup_mac` — `SIOCGIFFLAGS` writes the `ifr_flags`
    // union variant which is a `c_short`.
    let rc = unsafe { libc::ioctl(ctl.raw(), libc::SIOCGIFFLAGS, &mut req) };
    if rc < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("SIOCGIFFLAGS({interface})"));
    }
    // SAFETY: after a successful `SIOCGIFFLAGS`, the `ifr_flags` field is
    // populated by the kernel.
    let flags = unsafe { req.ifr_ifru.ifru_flags } as i32;
    Ok((flags & libc::IFF_UP != 0) && (flags & libc::IFF_RUNNING != 0))
}
