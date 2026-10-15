use super::env::{EnvConfig, PPPoETestEnv};
use super::runner::{ClientSpec, start_client, wait_for_exit, wait_for_running};
use super::scripted_server::{ScriptedServerMode, start_scripted_server};
use super::{MapSpaceCleanup, require_root};
use std::time::{Duration, Instant};

fn spec_from(cfg: &EnvConfig) -> ClientSpec {
    ClientSpec {
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        mtu: 1492,
        echo_interval_secs: None,
        redial_backoff_base_secs: None,
    }
}

/// Poll the scenario's pinned `tc_wan_egress_roots` prog array until the
/// client iface's entry (`key = ifindex`) reaches `want_present`.  The entry
/// is created by `WanLinkDataplane::new` when the link's service starts
/// and removed by its `close()` teardown — the chain-injected successor
/// of the old standalone `tc_pppoe_wan_egress` TC filter's
/// attach/detach lifecycle.
fn wait_for_egress_root_entry(
    scenario: &str,
    ifindex: u32,
    want_present: bool,
    timeout: Duration,
) -> bool {
    use libbpf_rs::{MapCore, MapHandle};

    let path = std::path::PathBuf::from("/sys/fs/bpf/landscape")
        .join(super::test_bpf_map_space(scenario))
        .join("tc_chain")
        .join("tc_wan_egress_roots");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let present = MapHandle::from_pinned_path(&path)
            .ok()
            .and_then(|map| {
                map.lookup(&ifindex.to_ne_bytes(), libbpf_rs::MapFlags::ANY).ok().flatten()
            })
            .is_some();
        if present == want_present {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Full session negotiation reaches `Running` (which — after the Running
/// semantics fix — is only signalled once the eBPF/system state is fully
/// applied), then a graceful stop ends in `Stop` and the client's LCP
/// Terminate-Request is answered by the server.
#[tokio::test]
#[ignore = "requires root, veth pairs and eBPF; run with --include-ignored"]
async fn basic_connect_and_stop() {
    require_root();
    // First binding → drops last, after the client exited and released its
    // map fds: removes this scenario's eBPF map space from bpffs.
    let _map_space_cleanup = MapSpaceCleanup::new("basic-connect");

    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        env.server_mac(),
        ScriptedServerMode::Success,
    );

    let client =
        start_client(env.client_ns(), "basic-connect", env.client_info(), &spec_from(&env_cfg));
    wait_for_running(&client.status, Duration::from_secs(30))
        .await
        .expect("client should reach Running after full negotiation");

    client.stop_and_join(Duration::from_secs(15)).expect("client should stop cleanly");
    server.wait().expect("server should observe the client termination");
    drop(env);
}

/// A server that rejects PAP via LCP Protocol-Reject makes the client fail
/// fatally: it must end in `Failed` WITHOUT ever reaching `Running`.
#[tokio::test]
#[ignore = "requires root, veth pairs and eBPF; run with --include-ignored"]
async fn pap_protocol_rejected_is_fatal() {
    require_root();
    let _map_space_cleanup = MapSpaceCleanup::new("pap-rejected");

    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        env.server_mac(),
        ScriptedServerMode::ProtocolRejectPap,
    );

    let client =
        start_client(env.client_ns(), "pap-rejected", env.client_info(), &spec_from(&env_cfg));
    let outcome =
        wait_for_exit(&client.status, Duration::from_secs(30)).await.expect("client should exit");

    assert!(
        !outcome.ever_running,
        "client must never reach Running when auth is protocol-rejected"
    );
    assert!(
        matches!(outcome.final_status, landscape_common::service::ServiceStatus::Failed),
        "client should end Failed, got {:?}",
        outcome.final_status
    );

    client.join(Duration::from_secs(5)).expect("client task should be finished");
    server.wait().expect("server script should complete");
    drop(env);
}

/// Server-side loss after establishment: the client's LCP echo keepalive
/// (1 s interval here) must detect the dead peer, redial (1 s backoff here)
/// and re-establish against a restarted server, while the service status
/// stays Running throughout (reconnect keeps the Running state).
#[tokio::test]
#[ignore = "requires root, veth pairs and eBPF; run with --include-ignored"]
async fn link_loss_triggers_redial_and_reconnect() {
    require_root();
    let _map_space_cleanup = MapSpaceCleanup::new("redial-reconnect");

    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");

    // Server #1: establishes a session, then vanishes.
    let server1 = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        env.server_mac(),
        ScriptedServerMode::SuccessThenVanish,
    );

    let spec = ClientSpec {
        echo_interval_secs: Some(1),
        redial_backoff_base_secs: Some(1),
        ..spec_from(&env_cfg)
    };
    let client = start_client(env.client_ns(), "redial-reconnect", env.client_info(), &spec);
    wait_for_running(&client.status, Duration::from_secs(30))
        .await
        .expect("first session should reach Running");
    server1.wait().expect("server #1 should vanish after establishment");

    // Real link loss: with the server side down nothing answers the client's
    // 1 s keepalive.  ~6 unanswered echoes (>5 failures) plus some margin.
    env.set_server_link(false).expect("bring server link down");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Server #2 comes back; the client redials (1 s backoff) and must
    // re-establish the session.  Re-establishment is observed server-side.
    let mut server2 = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        env.server_mac(),
        ScriptedServerMode::Success,
    );
    env.set_server_link(true).expect("bring server link back up");
    server2.established(Duration::from_secs(40)).expect("client should redial and reconnect");
    // `established` fires before the client-side setup finishes: wait for
    // proof that the new keepalive is running before stopping the client.
    server2
        .wait_keepalive_echo(Duration::from_secs(10))
        .expect("reconnected session keepalive should run");

    assert!(client.status.is_running(), "status should stay Running across the reconnect");

    client.stop_and_join(Duration::from_secs(15)).expect("client should stop cleanly");
    server2.wait().expect("server #2 should observe the client termination");
    drop(env);
}

/// BR-style forced teardown: after establishment the server sends a PPPoE
/// PADT.  The client must notice the PADT immediately (not after echo
/// timeouts) and redial without the backoff, while the service status stays
/// `Running`.  The 15 s backoff base makes the old behaviour (ignore PADT +
/// echo detection + backoff ≈ 20+ s) fail the 10 s budget below.
#[tokio::test]
#[ignore = "requires root, veth pairs and eBPF; run with --include-ignored"]
async fn padt_triggers_fast_redial() {
    require_root();
    let _map_space_cleanup = MapSpaceCleanup::new("padt-redial");

    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let mut server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        env.server_mac(),
        ScriptedServerMode::SuccessThenPadt,
    );

    // 1 s echo interval so that a *failure* to handle PADT would still be
    // caught by echo loss eventually; combined with the 15 s backoff base
    // the old behaviour cannot reconnect within the budget below.
    let spec = ClientSpec {
        echo_interval_secs: Some(1),
        redial_backoff_base_secs: Some(15),
        ..spec_from(&env_cfg)
    };
    let client = start_client(env.client_ns(), "padt-redial", env.client_info(), &spec);
    wait_for_running(&client.status, Duration::from_secs(30))
        .await
        .expect("first session should reach Running");

    // First establishment observed server-side; the server then sends PADT.
    server.established(Duration::from_secs(10)).expect("first session should be established");

    // The client must detect the PADT immediately and redial without the
    // backoff.  The PADT is sent on the client's first echo, so the whole
    // loop (echo → PADT → redial → second session) needs ~2 s; the budget
    // below leaves generous headroom for parallel-test load while still
    // failing for the old behaviour (ignore PADT + 6 s echo loss + 15 s
    // backoff ≥ 21 s).
    let started = Instant::now();
    server
        .established(Duration::from_secs(12))
        .expect("client should redial immediately after PADT");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "redial after PADT must skip the backoff, took {:?}",
        started.elapsed()
    );

    // Do not stop the client while it is still applying session #2's
    // system/eBPF state (the server-side notification happens before the
    // client-side setup finishes): wait for proof that the new keepalive is
    // running.
    server
        .wait_keepalive_echo(Duration::from_secs(10))
        .expect("second session keepalive should run");

    assert!(client.status.is_running(), "status should stay Running across the reconnect");

    client.stop_and_join(Duration::from_secs(15)).expect("client should stop cleanly");
    server.wait().expect("server should observe the client termination");
    drop(env);
}

/// After the session is established, the client iface's WAN egress chain
/// root is registered (keyed by ifindex in the pinned `tc_wan_egress_roots`
/// prog array) with the link's terminal PPPoE encap stage injected into the
/// chain; after the client stops, the last stage's teardown removes the
/// entry again.
#[tokio::test]
#[ignore = "requires root, veth pairs and eBPF; run with --include-ignored"]
async fn ebpf_pipeline_attaches_and_detaches() {
    require_root();
    // First binding → drops last, after the client exited and released its
    // map fds: removes this scenario's eBPF map space from bpffs.
    let _map_space_cleanup = MapSpaceCleanup::new("ebpf-pipeline");

    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        env.server_mac(),
        ScriptedServerMode::Success,
    );

    let client =
        start_client(env.client_ns(), "ebpf-pipeline", env.client_info(), &spec_from(&env_cfg));
    wait_for_running(&client.status, Duration::from_secs(30))
        .await
        .expect("client should reach Running");

    let ifindex = env.client_info().index;
    assert!(
        wait_for_egress_root_entry("ebpf-pipeline", ifindex, true, Duration::from_secs(5)),
        "WAN egress chain root should be registered for ifindex {ifindex} while running"
    );

    client.stop_and_join(Duration::from_secs(15)).expect("client should stop cleanly");

    assert!(
        wait_for_egress_root_entry("ebpf-pipeline", ifindex, false, Duration::from_secs(5)),
        "WAN egress chain root entry should be removed after the client stops"
    );

    server.wait().expect("server should observe the client termination");
    drop(env);
}
