//! Native XDP attachment policy and the guard for an attached program.

use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

use libbpf_rs::{Program, Xdp, XdpFlags, libbpf_sys};

use crate::LandscapeMapPath;
use crate::bpf_error::LdEbpfResult;

pub struct NativeXdpLink {
    ifindex: i32,
    prog_fd: i32,
}

impl NativeXdpLink {
    #[allow(clippy::field_reassign_with_default)]
    fn detach(ifindex: i32, prog_fd: i32) {
        let mut opts = libbpf_sys::bpf_xdp_attach_opts::default();
        opts.sz = size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t;
        opts.old_prog_fd = prog_fd;

        let ret = unsafe { libbpf_sys::bpf_xdp_detach(ifindex, XdpFlags::DRV_MODE.bits(), &opts) };
        if ret != 0 {
            tracing::debug!("detach native XDP ifindex={ifindex} failed: {}", -ret);
        }
    }
}

impl Drop for NativeXdpLink {
    fn drop(&mut self) {
        Self::detach(self.ifindex, self.prog_fd);
    }
}

/// The interfaces selected by the CLI's `--try-xdp` option.
pub struct XdpAttach {
    try_native: Option<Vec<i32>>,
}

impl XdpAttach {
    pub fn new(_paths: Arc<LandscapeMapPath>, try_native: Option<Vec<i32>>) -> Self {
        Self { try_native }
    }

    pub fn attach_native(&self, prog: &Program<'_>, ifindex: u32) -> LdEbpfResult<NativeXdpLink> {
        let ifindex = ifindex as i32;
        match &self.try_native {
            None => {
                return Err(crate::bpf_error::LandscapeEbpfError::Context {
                    context: format!(
                        "native XDP not enabled, use --try-xdp to enable (ifindex={ifindex})"
                    ),
                    source: libbpf_rs::Error::from_raw_os_error(libc::EOPNOTSUPP),
                });
            }
            Some(ifindices) => {
                if !ifindices.is_empty() && !ifindices.contains(&ifindex) {
                    return Err(crate::bpf_error::LandscapeEbpfError::Context {
                        context: format!(
                            "native XDP not enabled for this interface (ifindex={ifindex})"
                        ),
                        source: libbpf_rs::Error::from_raw_os_error(libc::EOPNOTSUPP),
                    });
                }
            }
        }

        let xdp = Xdp::new(prog.as_fd());
        let attach_flags = XdpFlags::DRV_MODE;

        crate::bpf_ctx!(xdp.attach(ifindex, attach_flags), "attach native XDP ifindex={ifindex}")?;

        let query = match crate::bpf_ctx!(
            xdp.query(ifindex, XdpFlags::DRV_MODE),
            "query native XDP ifindex={ifindex}"
        ) {
            Ok(query) => query,
            Err(err) => {
                NativeXdpLink::detach(ifindex, prog.as_fd().as_raw_fd());
                return Err(err.into());
            }
        };
        if query.drv_prog_id == 0 {
            NativeXdpLink::detach(ifindex, prog.as_fd().as_raw_fd());
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("native XDP attach missing drv prog id ifindex={ifindex}"),
                source: libbpf_rs::Error::from_raw_os_error(libc::ENODEV),
            });
        }

        Ok(NativeXdpLink { ifindex, prog_fd: prog.as_fd().as_raw_fd() })
    }
}
