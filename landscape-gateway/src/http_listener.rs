use super::*;
use pingora::services::Service;

#[derive(Clone, Copy, PartialEq)]
enum Completion {
    Starting,
    Stopped,
    Failed,
}

pub(super) struct HttpListener<S> {
    inner: S,
    shutdown: watch::Receiver<bool>,
    completion: Option<CompletionGuard>,
}

pub(super) struct HttpListenerShutdown {
    shutdown: watch::Sender<bool>,
    completion: watch::Receiver<Completion>,
    status: ServiceHandle,
    cleanup_uncertain: Arc<AtomicBool>,
}

pub(super) fn supervise<S: Service>(
    inner: S,
    cancel: CancellationToken,
    status: ServiceHandle,
    cleanup_uncertain: Arc<AtomicBool>,
) -> (HttpListener<S>, HttpListenerShutdown) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (completion_tx, completion_rx) = watch::channel(Completion::Starting);
    let guard = CompletionGuard {
        completion: completion_tx,
        cancel,
        status: status.clone(),
        cleanup_uncertain: cleanup_uncertain.clone(),
        completed: false,
    };
    (
        HttpListener {
            inner,
            shutdown: shutdown_rx,
            completion: Some(guard),
        },
        HttpListenerShutdown {
            shutdown: shutdown_tx,
            completion: completion_rx,
            status,
            cleanup_uncertain,
        },
    )
}

impl HttpListenerShutdown {
    pub(super) async fn shutdown_and_wait(&self) {
        self.shutdown.send_replace(true);
        let mut completion = self.completion.clone();
        if completion.wait_for(|result| *result != Completion::Starting).await.is_err() {
            self.cleanup_uncertain.store(true, Ordering::Release);
            self.status.just_change_status(ServiceStatus::Failed);
        }
    }

    pub(super) fn failed(&self) -> bool {
        *self.completion.borrow() == Completion::Failed
            || self.cleanup_uncertain.load(Ordering::Acquire)
    }
}

struct CompletionGuard {
    completion: watch::Sender<Completion>,
    cancel: CancellationToken,
    status: ServiceHandle,
    cleanup_uncertain: Arc<AtomicBool>,
    completed: bool,
}

impl CompletionGuard {
    fn complete(&mut self) {
        self.completed = true;
        let result = if self.cancel.is_cancelled() {
            Completion::Stopped
        } else {
            self.status.just_change_status(ServiceStatus::Failed);
            self.cancel.cancel();
            Completion::Failed
        };
        self.completion.send_replace(result);
    }
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        if !self.completed {
            // Unwinding or aborting the service does not join its spawned
            // accept tasks. Their listener cleanup cannot be confirmed.
            self.cleanup_uncertain.store(true, Ordering::Release);
            self.status.just_change_status(ServiceStatus::Failed);
            self.cancel.cancel();
            self.completion.send_replace(Completion::Failed);
        }
    }
}

#[async_trait::async_trait]
impl<S: Service> Service for HttpListener<S> {
    async fn start_service(
        &mut self,
        #[cfg(unix)] fds: Option<pingora::server::ListenFds>,
        _shutdown: pingora::server::ShutdownWatch,
        listeners_per_fd: usize,
    ) {
        let mut completion = self.completion.take().expect("HTTP service started twice");
        // Preserve the receiver's initial version: a stop requested before
        // startup must still be observed by Pingora's endpoint accept loops.
        self.inner
            .start_service(
                #[cfg(unix)]
                fds,
                self.shutdown.clone(),
                listeners_per_fd,
            )
            .await;
        // Pingora's listening service joins its accept tasks before returning.
        completion.complete();
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn threads(&self) -> Option<usize> {
        self.inner.threads()
    }

    fn runtime_opts_override(
        &self,
        global: &pingora::server::RuntimeOpts,
    ) -> Option<pingora::server::RuntimeOpts> {
        self.inner.runtime_opts_override(global)
    }

    fn on_startup_delay(&self, time_waited: Duration) {
        self.inner.on_startup_delay(time_waited);
    }

    fn listen_addresses(&self) -> Option<Vec<String>> {
        self.inner.listen_addresses()
    }
}
