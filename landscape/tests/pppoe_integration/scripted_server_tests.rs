use super::env::{ClientConfig, EnvConfig, PPPoETestEnv};
use super::require_root;
use super::runner::{run_client, ExpectOutcome};
use super::scripted_server::{start_scripted_server, ScriptedServerMode};
use landscape_common::net::MacAddr;

#[tokio::test]
async fn custom_server_ipcp_reject() {
    require_root();
    let mut env_cfg = EnvConfig::default();
    env_cfg.no_server = true;

    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let scripted_server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        MacAddr::from_str(&env_cfg.server_mac).expect("server mac"),
        ScriptedServerMode::IpcpReject,
    );
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 20,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Failure, None)
            .await;
    let server_result = scripted_server.wait();
    drop(env);

    assert!(server_result.is_ok(), "scripted server should reject IPCP: {server_result:?}");
    assert!(result.is_ok(), "client should fail on IPCP Reject: {result:?}");
}

#[tokio::test]
async fn custom_server_protocol_rejects_pap() {
    require_root();
    let mut env_cfg = EnvConfig::default();
    env_cfg.no_server = true;

    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let scripted_server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        MacAddr::from_str(&env_cfg.server_mac).expect("server mac"),
        ScriptedServerMode::ProtocolRejectPap,
    );
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 20,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Failure, None)
            .await;
    let server_result = scripted_server.wait();
    drop(env);

    assert!(server_result.is_ok(), "scripted server should reject PAP: {server_result:?}");
    assert!(result.is_ok(), "client should fail on PAP Protocol-Reject: {result:?}");
}

#[tokio::test]
async fn custom_server_protocol_rejects_ipcp() {
    require_root();
    let mut env_cfg = EnvConfig::default();
    env_cfg.no_server = true;

    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let scripted_server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        MacAddr::from_str(&env_cfg.server_mac).expect("server mac"),
        ScriptedServerMode::ProtocolRejectIpcp,
    );
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 20,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Failure, None)
            .await;
    let server_result = scripted_server.wait();
    drop(env);

    assert!(
        server_result.is_ok(),
        "scripted server should reject IPCP protocol: {server_result:?}"
    );
    assert!(result.is_ok(), "client should fail on IPCP Protocol-Reject: {result:?}");
}

#[tokio::test]
async fn custom_server_ipv6cp_nak() {
    require_root();
    let mut env_cfg = EnvConfig::default();
    env_cfg.no_server = true;

    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let scripted_server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        MacAddr::from_str(&env_cfg.server_mac).expect("server mac"),
        ScriptedServerMode::Ipv6cpNak,
    );
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 20,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Running, None)
            .await;
    let server_result = scripted_server.wait();
    drop(env);

    assert!(server_result.is_ok(), "scripted server should drive IPv6CP Nak: {server_result:?}");
    assert!(result.is_ok(), "client should handle IPv6CP Nak: {result:?}");
}

#[tokio::test]
async fn custom_server_ac_cookie_success() {
    require_root();
    let mut env_cfg = EnvConfig::default();
    env_cfg.no_server = true;

    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let scripted_server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        MacAddr::from_str(&env_cfg.server_mac).expect("server mac"),
        ScriptedServerMode::AcCookieSuccess,
    );
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 20,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Running, None)
            .await;
    let server_result = scripted_server.wait();
    drop(env);

    assert!(server_result.is_ok(), "client should echo AC-Cookie: {server_result:?}");
    assert!(result.is_ok(), "client should connect with AC-Cookie server: {result:?}");
}

#[tokio::test]
async fn chap_auth_success() {
    require_root();
    let mut env_cfg = EnvConfig::default();
    env_cfg.no_server = true;

    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let scripted_server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        MacAddr::from_str(&env_cfg.server_mac).expect("server mac"),
        ScriptedServerMode::ChapAuthSuccess,
    );
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 20,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Running, None)
            .await;
    let server_result = scripted_server.wait();
    drop(env);

    assert!(server_result.is_ok(), "scripted server CHAP handshake: {server_result:?}");
    assert!(result.is_ok(), "client should connect via CHAP: {result:?}");
}

#[tokio::test]
async fn chap_auth_failure() {
    require_root();
    let mut env_cfg = EnvConfig::default();
    env_cfg.no_server = true;

    let env = PPPoETestEnv::up(&env_cfg).expect("test environment should start");
    let scripted_server = start_scripted_server(
        env.server_ns().to_string(),
        env.server_iface().to_string(),
        MacAddr::from_str(&env_cfg.server_mac).expect("server mac"),
        ScriptedServerMode::ChapAuthFailure,
    );
    let client_cfg = ClientConfig {
        username: env_cfg.username.clone(),
        password: env_cfg.password.clone(),
        timeout_secs: 30,
        ..Default::default()
    };

    let result =
        run_client(env.client_ns(), env.client_info(), &client_cfg, ExpectOutcome::Failure, None)
            .await;
    let server_result = scripted_server.wait();
    drop(env);

    assert!(server_result.is_ok(), "scripted server CHAP failure: {server_result:?}");
    assert!(result.is_ok(), "client should fail on CHAP auth failure: {result:?}");
}
