use std::pin::Pin;
use std::task::{Context, Waker};

use tokio::sync::oneshot;

use super::*;

const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Config(&'static str, u32);

impl ServiceKeyProvider for Config {
    fn service_key(&self) -> String {
        self.0.to_owned()
    }
}

// The test releases startup and tracked cleanup separately for each instance.
#[derive(Debug)]
struct Run {
    config: Config,
    status: ServiceHandle,
    finish_start: oneshot::Sender<()>,
    finish_cleanup: oneshot::Sender<()>,
}

#[derive(Clone)]
struct Starter(mpsc::UnboundedSender<Run>);

#[async_trait::async_trait]
impl ServiceStarterTrait for Starter {
    type Config = Config;

    async fn start(&self, config: Config) -> ServiceHandle {
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        let (finish_start, startup) = oneshot::channel();
        let (finish_cleanup, cleanup) = oneshot::channel();
        self.0
            .send(Run {
                config,
                status: status.clone(),
                finish_start,
                finish_cleanup,
            })
            .unwrap();
        startup.await.unwrap();

        let worker = status.clone();
        status.spawn_task("service.test.cleanup", async move {
            worker.stop_token().cancelled().await;
            cleanup.await.unwrap();
            worker.just_change_status(ServiceStatus::Stop);
        });
        status.just_change_status(ServiceStatus::Running);
        status
    }
}

async fn setup() -> (ServiceManager<Starter>, mpsc::UnboundedReceiver<Run>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (ServiceManager::init(Vec::new(), Starter(tx)).await, rx)
}

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, future).await.expect("lifecycle operation stalled")
}

fn assert_pending<F: Future>(future: Pin<&mut F>) {
    assert!(future.poll(&mut Context::from_waker(Waker::noop())).is_pending());
}

fn abort_worker(manager: &ServiceManager<Starter>) -> watch::Receiver<Option<AbortHandle>> {
    let mut worker = manager.services.lock().unwrap()["wan"].registration.worker.clone();
    worker.borrow_and_update().as_ref().unwrap().abort();
    worker
}

#[tokio::test]
async fn delayed_restart_cannot_recreate_or_reach_a_new_registration() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let first = within(starts.recv()).await.unwrap();
    first.finish_start.send(()).unwrap();
    first.finish_cleanup.send(()).unwrap();
    let before_delete = manager.restart_existing(Config("wan", 2), TIMEOUT);
    let before_recreate = manager.restart_existing(Config("wan", 3), TIMEOUT);
    assert_eq!(within(manager.stop_service("wan".into())).await, Some(ServiceStatus::Stop));
    assert_eq!(before_delete.await, Err(RestartError::Closed));
    assert!(manager.get_all_status().await.is_empty());
    let while_absent = manager.restart_existing(Config("wan", 4), TIMEOUT);

    manager.update_service_wait(Config("wan", 5)).await;
    let new = within(starts.recv()).await.unwrap();
    assert_eq!(new.config, Config("wan", 5));
    assert_eq!(before_recreate.await, Err(RestartError::Closed));
    assert_eq!(while_absent.await, Err(RestartError::Closed));
    new.finish_start.send(()).unwrap();
    new.finish_cleanup.send(()).unwrap();
    within(manager.stop_all()).await;
}

#[tokio::test]
async fn delete_during_replacement_start_waits_until_its_tasks_finish() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let first = within(starts.recv()).await.unwrap();
    first.finish_start.send(()).unwrap();
    manager.restart_existing(Config("wan", 2), TIMEOUT).await.unwrap();
    within(first.status.stop_token().cancelled()).await;
    first.finish_cleanup.send(()).unwrap();

    let replacement = within(starts.recv()).await.unwrap();
    assert_eq!(replacement.config, Config("wan", 2));
    // Hold startup open, fill the queue, then start another delivery under backpressure.
    manager.restart_existing(Config("wan", 3), TIMEOUT).await.unwrap();
    assert_eq!(
        manager.restart_existing(Config("wan", 4), Duration::ZERO).await,
        Err(RestartError::TimedOut)
    );
    let blocked = manager.restart_existing(Config("wan", 4), TIMEOUT);
    tokio::pin!(blocked);
    assert_pending(blocked.as_mut());
    let delete = manager.stop_service("wan".into());
    tokio::pin!(delete);
    assert_pending(delete.as_mut());
    assert_eq!(within(blocked).await, Err(RestartError::Closed));

    replacement.finish_start.send(()).unwrap();
    within(replacement.status.stop_token().cancelled()).await;
    assert_pending(delete.as_mut());
    replacement.finish_cleanup.send(()).unwrap();
    assert_eq!(within(delete).await, Some(ServiceStatus::Stop));
    assert!(manager.get_all_status().await.is_empty());
    assert!(starts.try_recv().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recreate_waits_for_the_draining_key_and_leaves_other_keys_available() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let old = within(starts.recv()).await.unwrap();
    old.finish_start.send(()).unwrap();
    manager.restart_existing(Config("wan", 2), TIMEOUT).await.unwrap();
    within(old.status.stop_token().cancelled()).await;

    // Drop the delete future after requesting stop. Cleanup must still complete.
    {
        let delete = manager.stop_service("wan".into());
        tokio::pin!(delete);
        assert_pending(delete.as_mut());
    }
    assert!(within(manager.update_service(Config("wan", 2))).await.is_err());
    within(manager.update_service_wait(Config("wan", 3))).await;
    manager.update_service_wait(Config("lan", 1)).await;
    let lan = within(starts.recv()).await.unwrap();
    assert_eq!(lan.config, Config("lan", 1));
    lan.finish_start.send(()).unwrap();
    old.finish_cleanup.send(()).unwrap();

    let new = within(starts.recv()).await.unwrap();
    assert_eq!(old.status.current(), ServiceStatus::Stop);
    assert_eq!(new.config, Config("wan", 3));
    let shutdown = manager.stop_all();
    tokio::pin!(shutdown);
    assert_pending(shutdown.as_mut());
    within(lan.status.stop_token().cancelled()).await;
    lan.finish_cleanup.send(()).unwrap();
    new.finish_start.send(()).unwrap();
    within(new.status.stop_token().cancelled()).await;
    assert_pending(shutdown.as_mut());
    new.finish_cleanup.send(()).unwrap();
    within(shutdown).await;
    assert!(manager.get_all_status().await.is_empty());
}

#[tokio::test]
async fn a_waiting_upsert_recovers_an_unexpected_worker_exit() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let _starting = within(starts.recv()).await.unwrap();
    let stale_restart = manager.restart_existing(Config("wan", 2), TIMEOUT);
    manager.update_service_wait(Config("wan", 2)).await;
    let save = manager.update_service_wait(Config("wan", 3));
    tokio::pin!(save);
    assert_pending(save.as_mut());

    abort_worker(&manager);
    within(save).await;
    let queued = within(starts.recv()).await.unwrap();
    assert_eq!(queued.config, Config("wan", 2));
    queued.finish_start.send(()).unwrap();
    queued.finish_cleanup.send(()).unwrap();
    let recovered = within(starts.recv()).await.unwrap();
    assert_eq!(recovered.config, Config("wan", 3));
    assert_eq!(stale_restart.await, Err(RestartError::Closed));
    recovered.finish_start.send(()).unwrap();
    recovered.finish_cleanup.send(()).unwrap();
    within(manager.stop_all()).await;
}

#[tokio::test]
async fn a_second_delete_withdraws_a_waiting_recreation() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let old = within(starts.recv()).await.unwrap();
    old.finish_start.send(()).unwrap();
    let first_delete = manager.stop_service("wan".into());
    tokio::pin!(first_delete);
    assert_pending(first_delete.as_mut());
    within(old.status.stop_token().cancelled()).await;

    within(manager.update_service_wait(Config("wan", 2))).await;
    let second_delete = manager.stop_service("wan".into());
    tokio::pin!(second_delete);
    assert_pending(second_delete.as_mut());
    old.finish_cleanup.send(()).unwrap();
    within(first_delete).await;
    within(second_delete).await;
    assert!(manager.get_all_status().await.is_empty());
    assert!(starts.try_recv().is_err());
}

#[tokio::test]
async fn worker_failure_during_cleanup_does_not_overlap_runs() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let old = within(starts.recv()).await.unwrap();
    old.finish_start.send(()).unwrap();
    manager.update_service_wait(Config("wan", 2)).await;
    within(old.status.stop_token().cancelled()).await;
    let mut worker = abort_worker(&manager);
    within(worker.changed()).await.unwrap();
    assert!(worker.borrow().is_none());
    manager.update_service(Config("wan", 3)).await.unwrap();
    assert!(starts.try_recv().is_err(), "replacement started during tracked cleanup");
    old.finish_cleanup.send(()).unwrap();
    let recovered = within(starts.recv()).await.unwrap();
    assert_eq!(old.status.current(), ServiceStatus::Stop);
    assert_eq!(recovered.config, Config("wan", 2));
    recovered.finish_start.send(()).unwrap();
    recovered.finish_cleanup.send(()).unwrap();
    let latest = within(starts.recv()).await.unwrap();
    assert_eq!(latest.config, Config("wan", 3));
    latest.finish_start.send(()).unwrap();
    latest.finish_cleanup.send(()).unwrap();
    within(manager.stop_all()).await;
}

#[tokio::test]
async fn waiting_writes_keep_their_order_across_worker_failure() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let _starting = within(starts.recv()).await.unwrap();
    manager.update_service_wait(Config("wan", 2)).await;
    let older = manager.update_service_wait(Config("wan", 3));
    let newer = manager.update_service_wait(Config("wan", 4));
    tokio::pin!(older, newer);
    assert_pending(older.as_mut());
    assert_pending(newer.as_mut());
    abort_worker(&manager);

    let drain = async {
        let mut seen = Vec::new();
        loop {
            let run = starts.recv().await.unwrap();
            seen.push(run.config.1);
            run.finish_start.send(()).unwrap();
            run.finish_cleanup.send(()).unwrap();
            if seen.last() == Some(&4) {
                break;
            }
        }
        seen
    };
    let (_, _, seen) = within(async { tokio::join!(older, newer, drain) }).await;
    assert_eq!(seen, [2, 3, 4]);
    within(manager.stop_all()).await;
}

#[tokio::test]
async fn delete_during_recovery_discards_writes_for_that_registration() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let old = within(starts.recv()).await.unwrap();
    old.finish_start.send(()).unwrap();
    manager.update_service_wait(Config("wan", 2)).await;
    within(old.status.stop_token().cancelled()).await;
    let mut worker = abort_worker(&manager);
    within(worker.changed()).await.unwrap();

    manager.update_service_wait(Config("wan", 3)).await;
    let waiting = manager.update_service_wait(Config("wan", 4));
    tokio::pin!(waiting);
    assert_pending(waiting.as_mut());
    let delete = manager.stop_service("wan".into());
    tokio::pin!(delete);
    assert_pending(delete.as_mut());
    manager.update_service_wait(Config("wan", 5)).await;
    within(waiting).await;

    old.finish_cleanup.send(()).unwrap();
    within(delete).await;
    let new = within(starts.recv()).await.unwrap();
    assert_eq!(new.config, Config("wan", 5));
    new.finish_start.send(()).unwrap();
    new.finish_cleanup.send(()).unwrap();
    within(manager.stop_all()).await;
    assert!(starts.try_recv().is_err());
}

#[tokio::test]
async fn replacing_an_idle_worker_preserves_its_healthy_run() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let run = within(starts.recv()).await.unwrap();
    run.finish_start.send(()).unwrap();
    within(async {
        while !ServiceHandle::ptr_eq(
            &manager.services.lock().unwrap()["wan"].registration.runs.current_run(),
            &run.status,
        ) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let mut worker = manager.services.lock().unwrap()["wan"].registration.worker.clone();
    let old_worker = worker.borrow_and_update().as_ref().unwrap().clone();
    old_worker.abort();
    within(worker.wait_for(|next| next.as_ref().is_some_and(|task| task.id() != old_worker.id())))
        .await
        .unwrap();
    assert_eq!(run.status.current(), ServiceStatus::Running);
    assert!(!run.status.stop_token().is_cancelled());
    assert!(starts.try_recv().is_err());

    manager.update_service_wait(Config("wan", 2)).await;
    within(run.status.stop_token().cancelled()).await;
    run.finish_cleanup.send(()).unwrap();
    let next = within(starts.recv()).await.unwrap();
    assert_eq!(next.config, Config("wan", 2));
    next.finish_start.send(()).unwrap();
    next.finish_cleanup.send(()).unwrap();
    within(manager.stop_all()).await;
}

#[tokio::test]
async fn a_waiting_save_recovers_the_supervisor_without_restarting_the_worker() {
    let (manager, mut starts) = setup().await;
    manager.update_service_wait(Config("wan", 1)).await;
    let first = within(starts.recv()).await.unwrap();
    manager.update_service_wait(Config("wan", 2)).await;
    let third = manager.update_service_wait(Config("wan", 3));
    tokio::pin!(third);
    assert_pending(third.as_mut());

    let done = {
        let services = manager.services.lock().unwrap();
        let entry = &services["wan"];
        entry.supervisor.as_ref().unwrap().abort();
        entry.supervisor_done.clone()
    };
    within(done.cancelled()).await;
    assert_pending(third.as_mut());
    assert!(!manager.services.lock().unwrap()["wan"].supervisor_done.is_cancelled());
    first.finish_start.send(()).unwrap();
    first.finish_cleanup.send(()).unwrap();
    within(third).await;
    for number in [2, 3] {
        let next = within(starts.recv()).await.unwrap();
        assert_eq!(next.config, Config("wan", number));
        next.finish_start.send(()).unwrap();
        next.finish_cleanup.send(()).unwrap();
    }
    within(manager.stop_all()).await;
}

#[test]
fn a_save_after_runtime_shutdown_restores_the_consumer() {
    let runtime = || tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let old_runtime = runtime();
    let (manager, mut starts) = old_runtime.block_on(setup());
    let _interrupted = old_runtime.block_on(async {
        manager.update_service_wait(Config("wan", 1)).await;
        within(starts.recv()).await.unwrap()
    });
    drop(old_runtime);
    runtime().block_on(async {
        within(manager.update_service_wait(Config("wan", 2))).await;
        let run = within(starts.recv()).await.unwrap();
        assert_eq!(run.config, Config("wan", 2));
        run.finish_start.send(()).unwrap();
        run.finish_cleanup.send(()).unwrap();
        within(manager.stop_all()).await;
    });
}
