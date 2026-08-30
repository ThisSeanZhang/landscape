use super::cmd::cmd_output;
use super::env::{ClientConfig, EnvConfig, PPPoETestEnv};
use super::require_root;
use super::runner::{run_client, ExpectOutcome};
use std::time::{Duration, Instant};

/// Wait until `tc filter show egress` on `iface` (in `client_ns`) contains
/// `needle`, or the deadline passes.  Returns the last filter output.
fn wait_for_egress_filter(client_ns: &str, iface: &str, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut tc = String::new();
    while Instant::now() < deadline {
        tc = cmd_output(
            "ip",
            &["netns", "exec", client_ns, "tc", "filter", "show", "dev", iface, "egress"],
        )
        .expect("tc filter show egress should succeed");
        if tc.contains(needle) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    tc
}

/// After the PPPoE session is established, the client's eBPF pipeline must
/// be active on this test's own interface: the `tc_pppoe_wan_egress` TC
/// filter is attached to the client veth.  (Reaching `Running` already
/// implies the pipeline setup succeeded; the filter is this test's own
/// observable artifact, unlike the pipeline maps, which are process-global
/// shared maps pinned by whatever client connected first.)
#[tokio::test]
async fn ebpf_pipeline_attaches_after_connection() {
    require_root();

    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        ..Default::default()
    };

    let client_ns = env.client_ns().to_string();
    let iface_name = env.client_info().name.clone();

    let result = run_client(
        env.client_ns(),
        env.client_info(),
        &client_cfg,
        ExpectOutcome::Running,
        Some(Box::new(move || {
            // The egress TC filter (tc_pppoe_wan_egress) is attached to the
            // client interface.  Poll for it: the client's eBPF thread
            // attaches it asynchronously after Running and parallel load can
            // delay that (RTNL contention).
            let tc = wait_for_egress_filter(
                &client_ns,
                &iface_name,
                "tc_pppoe_wan_eg",
                Duration::from_secs(5),
            );
            // The kernel truncates the program name to 15 chars.
            assert!(
                tc.contains("tc_pppoe_wan_eg"),
                "egress filter should reference tc_pppoe_wan_egress, got: {tc}"
            );
        })),
    )
    .await;
    drop(env);

    assert!(result.is_ok(), "client should connect and activate eBPF pipeline: {result:?}");
}

/// When the client stops, the TC hook it attached must be detached again
/// (TcHookProxy drops its filter on teardown).  This is the per-interface
/// cleanup signal; the shared pipeline maps intentionally persist.
#[tokio::test]
async fn ebpf_pipeline_detached_after_client_stop() {
    require_root();

    let env_cfg = EnvConfig::default();
    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        ..Default::default()
    };

    let client_ns = env.client_ns().to_string();
    let iface_name = env.client_info().name.clone();

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Stop, None)
            .await;

    assert!(result.is_ok(), "client should connect and stop without error: {result:?}");

    // The egress TC filter the client attached must be gone after the stop.
    // (Checked while the client netns still exists; `run_client` joins the
    // client thread, so the hook's Drop has already run.)
    let tc = cmd_output(
        "ip",
        &["netns", "exec", &client_ns, "tc", "filter", "show", "dev", &iface_name, "egress"],
    )
    .expect("tc filter show egress should succeed");
    assert!(
        !tc.contains("tc_pppoe_wan_eg"),
        "egress filter should be detached after client stop, got: {tc}"
    );

    drop(env);
}
