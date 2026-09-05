use super::cmd::cmd_output;
use super::env::{EnvConfig, PPPoETestEnv};
use super::runner::{start_client, wait_for_exit, wait_for_running, ClientSpec};
use super::scripted_server::{start_scripted_server, ScriptedServerMode};
use super::require_root;
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

/// Poll `tc filter show egress` inside the client namespace until the output
/// contains `needle`, returning the last output either way.
fn wait_for_egress_filter(client_ns: &str, iface: &str, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        last = cmd_output(
            "ip",
            &["netns", "exec", client_ns, "tc", "filter", "show", "egress", "dev", iface],
        )
        .unwrap_or_default();
        if last.contains(needle) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    last
}

/// Full session negotiation reaches `Running` (which — after the Running
/// semantics fix — is only signalled once the eBPF/system state is fully
/// applied), then a graceful stop ends in `Stop` and the client's LCP
/// Terminate-Request is answered by the server.
#[tokio::test]
#[ignore = "requires root, veth pairs and eBPF; run with --include-ignored"]
async fn basic_connect_and_stop() {
    require_root();

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
    let server2 = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        env.server_mac(),
        ScriptedServerMode::Success,
    );
    env.set_server_link(true).expect("bring server link back up");
    server2.established(Duration::from_secs(40)).expect("client should redial and reconnect");

    assert!(client.status.is_running(), "status should stay Running across the reconnect");

    client.stop_and_join(Duration::from_secs(15)).expect("client should stop cleanly");
    server2.wait().expect("server #2 should observe the client termination");
    drop(env);
}

/// After the session is established, the `tc_pppoe_wan_egress` TC filter is
/// attached to the client veth; after the client stops, the filter is
/// detached again (TcHookProxy teardown).
#[tokio::test]
#[ignore = "requires root, veth pairs and eBPF; run with --include-ignored"]
async fn ebpf_pipeline_attaches_and_detaches() {
    require_root();

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

    // The kernel truncates the program name to 15 chars.
    let iface_name = env.client_info().name.clone();
    let client_ns = env.client_ns().to_string();
    let tc =
        wait_for_egress_filter(&client_ns, &iface_name, "tc_pppoe_wan_eg", Duration::from_secs(5));
    assert!(
        tc.contains("tc_pppoe_wan_eg"),
        "egress filter should reference tc_pppoe_wan_egress, got: {tc}"
    );

    client.stop_and_join(Duration::from_secs(15)).expect("client should stop cleanly");

    let detach_deadline = Instant::now() + Duration::from_secs(5);
    let mut detached = false;
    while Instant::now() < detach_deadline {
        let out = cmd_output(
            "ip",
            &["netns", "exec", &client_ns, "tc", "filter", "show", "egress", "dev", &iface_name],
        )
        .unwrap_or_default();
        if !out.contains("tc_pppoe_wan_eg") {
            detached = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(detached, "egress filter should be detached after the client stops");

    server.wait().expect("server should observe the client termination");
    drop(env);
}
