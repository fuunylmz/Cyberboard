use cyberboard_config_compiler::{ConfigProfile, compile_config};
use serde_json::Value;
use std::{fs, process::Command};

fn fixture(name: &str) -> (ConfigProfile, Value) {
    let root = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let input: ConfigProfile = serde_json::from_slice(
        &fs::read(format!("{root}.input.json")).expect("read input fixture"),
    )
    .expect("decode profile fixture");
    let expected: Value = serde_json::from_slice(
        &fs::read(format!("{root}.expected.json")).expect("read expected fixture"),
    )
    .expect("decode expected fixture");
    (input, expected)
}

#[test]
fn golden_server_configs_match_fixtures() {
    for name in ["vless-tls", "vmess-websocket", "trojan-tls"] {
        let (profile, expected) = fixture(name);
        let actual = compile_config(&profile).expect("compile profile");
        assert_eq!(actual, expected, "golden output differs for {name}");
    }
}

#[test]
fn typed_adapter_serializes_to_the_compiled_json() {
    let (profile, expected) = fixture("vless-tls");
    let config = cyberboard_config_compiler::adapters::singbox::SingBoxAdapter
        .render(&profile)
        .expect("render typed config");
    assert_eq!(serde_json::to_value(config).unwrap(), expected);
}

#[test]
fn fixture_configs_pass_sing_box_check_when_binary_is_available() {
    let binary = std::env::var_os("CYBERBOARD_SING_BOX_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "sing-box".into());
    let version = Command::new(&binary).arg("version").output();
    let Ok(version) = version else {
        eprintln!("skipping sing-box check; binary not available: {binary:?}");
        return;
    };
    let version_text = format!(
        "{}{}",
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr)
    );
    if !version_text.contains("with_v2ray_api") {
        eprintln!("skipping sing-box check; binary lacks with_v2ray_api: {binary:?}");
        return;
    }

    for name in ["vless-tls", "vmess-websocket", "trojan-tls"] {
        let (profile, _) = fixture(name);
        cyberboard_config_compiler::adapters::singbox::SingBoxAdapter
            .check_with_binary(&profile, &binary)
            .unwrap_or_else(|error| panic!("sing-box check failed for {name}: {error}"));
    }
}
