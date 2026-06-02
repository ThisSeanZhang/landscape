use std::{mem::MaybeUninit, os::fd::AsFd, ptr::NonNull};

use libbpf_rs::{OpenMapMut, OpenObject, Program, TcAttachPoint, TcHook, TcHookBuilder};

pub(crate) struct OwnedOpenObject {
    ptr: NonNull<MaybeUninit<OpenObject>>,
}

impl OwnedOpenObject {
    pub fn new() -> (Self, &'static mut MaybeUninit<OpenObject>) {
        let ptr = NonNull::from(Box::leak(Box::new(MaybeUninit::<OpenObject>::uninit())));
        let object = unsafe { ptr.as_ptr().as_mut().expect("backing open object pointer is null") };
        (Self { ptr }, object)
    }
}

impl Drop for OwnedOpenObject {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.ptr.as_ptr()));
        }
    }
}

unsafe impl Send for OwnedOpenObject {}
unsafe impl Sync for OwnedOpenObject {}

pub(crate) fn pin_and_reuse_map(
    map: &mut OpenMapMut<'_>,
    path: &std::path::Path,
) -> crate::bpf_error::LdEbpfResult<()> {
    map.set_pin_path(path).map_err(|source| crate::bpf_error::LandscapeEbpfError::Context {
        context: "set_pin_path failed".to_string(),
        source,
    })?;
    map.reuse_pinned_map(path).map_err(|source| crate::bpf_error::LandscapeEbpfError::Context {
        context: "reuse_pinned_map failed".to_string(),
        source,
    })?;
    Ok(())
}

pub struct TcHookProxy {
    hook: Option<TcHook>,
}

impl TcHookProxy {
    pub fn new(prog: &Program, ifindex: i32, attach: TcAttachPoint, priority: u32) -> TcHookProxy {
        let mut tc_builder = TcHookBuilder::new(prog.as_fd());
        tc_builder.ifindex(ifindex).replace(true).handle(1).priority(priority);
        let hook = tc_builder.hook(attach);
        Self { hook: Some(hook) }
    }

    pub fn attach(&mut self) {
        if let Some(hook) = self.hook.as_mut() {
            let result = hook.query();
            tracing::debug!("1 - the hook is exist? {:?}", result);
            hook.create().unwrap();

            let result = hook.query();
            tracing::debug!("2 - the hook is exist? {:?}", result);
            hook.attach().unwrap();

            let result = hook.query();
            tracing::debug!("3 - the hook is exist? {:?}", result);
        }
    }
}

impl Drop for TcHookProxy {
    fn drop(&mut self) {
        if let Some(mut hook) = self.hook {
            tracing::debug!("detach hook");
            if let Ok(_) = hook.query() {
                tracing::debug!("start detach success");
                if let Err(e) = hook.detach() {
                    tracing::debug!("detach error: {:?}", e);
                } else {
                    tracing::debug!("detach success");
                }
            }
        }
    }
}

// TC operations are thread-safe as they are system calls on file descriptors
// and don't share mutable state across threads
unsafe impl Send for TcHookProxy {}
unsafe impl Sync for TcHookProxy {}
