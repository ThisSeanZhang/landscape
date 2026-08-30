use super::cmd::cmd_ok;
use super::env::{ClientConfig, EnvConfig, PPPoETestEnv};
use super::require_root;
use super::runner::{run_client, ExpectOutcome};
use std::process::Command;

#[tokio::test]
async fn basic_connection() {
    require_root();
    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Running, None)
            .await;
    drop(env);

    assert!(result.is_ok(), "basic connection should succeed: {result:?}");
}

#[tokio::test]
async fn auth_failure() {
    require_root();
    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");

    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: "wrong-password".into(),
        timeout_secs: 15,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Failure, None)
            .await;
    drop(env);

    assert!(result.is_ok(), "auth failure test should succeed (client fails): {result:?}");
}

/// The PPPoE client code treats IPv6CP rejection as "confirmed" (the client
/// does not require IPv6CP to succeed).  Therefore a server that refuses
/// IPv6CP still results in a successful connection (Running).
#[tokio::test]
async fn ipv6cp_rejection() {
    require_root();
    let env_cfg = EnvConfig {
        enable_ipv6cp: false, // server refuses IPv6CP
        ..Default::default()
    };

    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 15,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Running, None)
            .await;
    drop(env);

    assert!(result.is_ok(), "IPv6CP rejection should NOT prevent connection: {result:?}");
}

/// After the PPPoE connection is established, bring down the server-side
/// interface.  The client should detect the failure via LCP echo keepalive
/// timeout and transition to Failed/Stop.  The client fails on the 6th
/// consecutive unanswered echo (see runtime echo loop: `echo_failures > 5`);
/// with the 3 s test interval that is ≈ 18 s instead of ~2 minutes.
#[tokio::test]
async fn disconnect_detection() {
    require_root();
    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");

    // Capture what we need for the disconnect trigger – the closure must be
    // `Send` (tokio may move the async task across threads), so we clone
    // `String` values rather than capturing `&env`.
    let server_ns = env.server_ns().to_string();
    let server_iface = env.server_iface().to_string();

    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 60,
        echo_interval_secs: Some(3),
        ..Default::default()
    };

    // LCP echo keepalive uses a 3 s interval (see `echo_interval_secs`);
    // the client fails on the 6th consecutive unanswered echo, i.e. ≈ 18 s
    // after the link goes down.  A 60 s post-run timeout leaves headroom.
    let result = run_client(
        env.client_ns(),
        env.client_info(),
        &client_cfg,
        ExpectOutcome::FailedAfterRunning { post_run_timeout_secs: 60 },
        Some(Box::new(move || {
            cmd_ok(
                "ip",
                &["netns", "exec", &server_ns, "ip", "link", "set", &server_iface, "down"],
            )
            .expect("bring server iface down");
        })),
    )
    .await;
    drop(env);

    assert!(result.is_ok(), "disconnect detection should succeed: {result:?}");
}

/// Simulate an unreachable PPPoE server — the client sends PADI but never
/// receives PADO.  The discovery phase should time out and the client
/// should transition to Failed without ever reaching Running.
#[tokio::test]
async fn server_not_responding() {
    require_root();
    let env_cfg = EnvConfig {
        no_server: true, // never start pppoe-server
        ..Default::default()
    };

    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 20,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Failure, None)
            .await;
    drop(env);

    assert!(result.is_ok(), "client should fail when server never responds: {result:?}");
}

/// After the connection is established, kill everything inside the server
/// namespace (pppoe-server and its session pppd).  The client should detect
/// the loss of the peer and transition to Failed/Stop.
///
/// Why kill by netns instead of by PID/pkill: the spawned `ip netns exec`
/// wrapper's PID is not pppoe-server itself (SIGKILL on the wrapper does not
/// propagate), and a host-wide `pkill pppd` would also kill other tests'
/// pppd instances when the suite runs in parallel.  Killing the processes
/// listed by `ip netns pids` is both effective and scoped to this test's
/// server namespace.
#[tokio::test]
async fn server_process_killed() {
    require_root();
    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");

    let server_ns = env.server_ns().to_string();

    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 30,
        echo_interval_secs: Some(3),
        ..Default::default()
    };

    // When the client reaches Running, SIGKILL every process in the server
    // netns (pppoe-server + pppd).  LCP echo timeout is 6 × 3 s = ~18 s;
    // 60 s gives comfortable headroom.
    let result = run_client(
        env.client_ns(),
        env.client_info(),
        &client_cfg,
        ExpectOutcome::FailedAfterRunning { post_run_timeout_secs: 60 },
        Some(Box::new(move || {
            let out = Command::new("ip")
                .args(["netns", "pids", &server_ns])
                .output()
                .expect("ip netns pids should run");
            assert!(out.status.success(), "ip netns pids failed: {:?}", out);
            let pids: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            assert!(
                !pids.is_empty(),
                "expected at least pppoe-server + pppd in server netns {server_ns}"
            );
            for pid in pids {
                let pid: i32 = pid.parse().expect("netns pid should be numeric");
                let ret = unsafe { libc::kill(pid, libc::SIGKILL) };
                assert_eq!(ret, 0, "kill pid {pid} failed");
            }
        })),
    )
    .await;
    drop(env);

    assert!(result.is_ok(), "client should detect killed server: {result:?}");
}

/// The server sends an LCP Terminate-Request shortly after the connection
/// is established (via `maxconnect 5` in pppd options).  The client
/// should handle the clean termination gracefully and transition to Stop.
///
/// # Why this test is `#[ignore]`d (cannot run in parallel)
///
/// `maxconnect 5` makes the server terminate the session 5 seconds after
/// it comes up, so the client must finish negotiation and reach `Running`
/// within that window.  Running the full suite in parallel spawns many
/// netns/veth pairs, pppoe-server/pppd instances and eBPF loads at once;
/// kernel-global serialization points (the RTNL mutex for TC attaches, BPF
/// verifier/loading, `ip netns add/del`) slow each test's negotiation down,
/// its retransmit backoff (3 s × 2, 3, 4, …) easily blows past 5 s and the
/// client never reaches `Running` before the runner's `timeout_secs` fires.
/// Other tests are immune: they have no time window racing the client, so
/// the suite is otherwise parallel-safe.  Run this one solo:
///
/// ```sh
/// cargo test -p landscape --test pppoe_integration -- --ignored server_sends_terminate
/// ```
#[tokio::test]
#[ignore = "timing-sensitive (maxconnect 5 vs negotiation speed under parallel load); run solo, see doc comment"]
async fn server_sends_terminate() {
    require_root();
    let env_cfg = EnvConfig {
        extra_pppd_options: vec!["maxconnect 5".into()],
        ..Default::default()
    };
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 30,
        ..Default::default()
    };

    let result = run_client(
        env.client_ns(),
        env.client_info(),
        &client_cfg,
        ExpectOutcome::FailedAfterRunning { post_run_timeout_secs: 30 },
        None,
    )
    .await;
    drop(env);

    assert!(result.is_ok(), "client should handle server-initiated terminate: {result:?}");
}

/// After the PPPoE connection is established, trigger a graceful stop from
/// the client side (by setting `ServiceStatus::Stopping`).  The client
/// should send an LCP Terminate-Request, clean up, and exit with `Stop`.
#[tokio::test]
async fn client_initiated_stop() {
    require_root();
    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");

    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 30,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Stop, None)
            .await;
    drop(env);

    assert!(result.is_ok(), "client-initiated stop should succeed: {result:?}");
}

/// The server is configured with a smaller MRU (`mtu 1400` in pppd options)
/// than the client's default (1492).  The server should Nak the client's
/// MRU and the client should accept the suggested value and renegotiate.
#[tokio::test]
async fn lcp_mru_negotiation() {
    require_root();
    let env_cfg = EnvConfig {
        extra_pppd_options: vec!["mtu 1400".into()],
        ..Default::default()
    };
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 30,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Running, None)
            .await;
    drop(env);

    assert!(result.is_ok(), "LCP MRU negotiation should succeed: {result:?}");
}

/// Same as `basic_connection` but with `default_router = true`, which
/// causes the client to install a default route via the peer and register
/// the route with the global `LD_ALL_ROUTERS` manager.
#[tokio::test]
async fn basic_connection_with_default_route() {
    require_root();
    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");

    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        default_router: true,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Running, None)
            .await;
    drop(env);

    assert!(result.is_ok(), "basic connection with default route should succeed: {result:?}");
}
