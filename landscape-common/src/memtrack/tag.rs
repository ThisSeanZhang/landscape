//! 归属标签:线程本地当前子系统槽位 ID。
//!
//! tokio 任务可能在线程间迁移,因此标签不能在线程启动时一次设置,而是由
//! `TaggedFuture` 在**每次 poll** 时设置、poll 结束后恢复,保证异步任务无论
//! 落在哪个 worker 线程上都正确归属。专用线程(`ld-fw-*` 等)则在线程入口
//! 一次设置、长期有效。

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::registry::UNATTRIBUTED;

thread_local! {
    static CURRENT_TAG: Cell<usize> = const { Cell::new(UNATTRIBUTED) };
}

/// 读取当前线程的归属标签(分配器热路径使用;mem-track 未开启时无调用方)。
#[cfg_attr(not(feature = "mem-track"), allow(dead_code))]
#[inline]
pub(crate) fn current_tag() -> usize {
    CURRENT_TAG.with(|tag| tag.get())
}

/// 在 `f` 执行期间将当前线程归属到 `tag`,结束后恢复原值(含 panic 路径:
/// Drop guard 保证恢复,否则任务 panic 被捕获后线程标签会残留)。
#[inline]
pub fn with_tag<T>(tag: usize, f: impl FnOnce() -> T) -> T {
    struct Restore(usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT_TAG.with(|t| t.set(self.0));
        }
    }
    let prev = CURRENT_TAG.with(|t| t.replace(tag));
    let _restore = Restore(prev);
    f()
}

/// 包装 future,使其每次 poll 期间当前线程归属到 `tag`。
///
/// 内部用 `Pin<Box<F>>` 做安全的固定投影,每个任务 spawn 时仅多一次堆分配。
pub struct TaggedFuture<F> {
    tag: usize,
    inner: Pin<Box<F>>,
}

impl<F> TaggedFuture<F> {
    pub fn new(tag: usize, future: F) -> Self {
        TaggedFuture { tag, inner: Box::pin(future) }
    }
}

impl<F: Future> Future for TaggedFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        let inner = this.inner.as_mut();
        with_tag(this.tag, || inner.poll(cx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_tag_sets_and_restores() {
        let prev = current_tag();
        let seen = with_tag(3, || {
            let inner = with_tag(5, current_tag);
            assert_eq!(inner, 5);
            current_tag()
        });
        assert_eq!(seen, 3);
        assert_eq!(current_tag(), prev);
    }

    #[test]
    fn with_tag_restores_on_panic() {
        let prev = current_tag();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_tag(7, || panic!("tag must still be restored"));
        }));
        assert!(caught.is_err());
        assert_eq!(current_tag(), prev);
    }

    #[tokio::test]
    async fn tagged_future_attributed_during_poll() {
        let first = TaggedFuture::new(1, async {
            assert_eq!(current_tag(), 1);
            tokio::task::yield_now().await;
            // yield 后重新 poll,标签必须仍然生效(模拟线程迁移后重新设置)。
            assert_eq!(current_tag(), 1);
        });
        let second = TaggedFuture::new(2, async {
            assert_eq!(current_tag(), 2);
        });
        let ((), ()) = tokio::join!(first, second);
    }
}
