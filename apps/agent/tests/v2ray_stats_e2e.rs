use std::{
    io::{Read, Write},
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use cyberboard_agent_protocol::v2rayapi::{
    QueryStatsRequest, stats_service_client::StatsServiceClient,
};
use serde_json::json;
use tempfile::tempdir;
use tokio::{process::Command, time::sleep};
use tonic::Request;
use uuid::Uuid;

fn sing_box_binary() -> Option<PathBuf> {
    std::env::var_os("CYBERBOARD_SING_BOX_BINARY")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|directory| directory.join("sing-box"))
                .find(|path| path.is_file())
        })
}

async fn stats(endpoint: &str) -> Result<Vec<(String, i64)>, String> {
    let mut client = StatsServiceClient::connect(endpoint.to_owned())
        .await
        .map_err(|error| error.to_string())?;
    let response = client
        .query_stats(Request::new(QueryStatsRequest {
            pattern: String::new(),
            reset: true,
            patterns: vec!["user>>>".into()],
            regexp: false,
        }))
        .await
        .map_err(|error| error.to_string())?
        .into_inner();
    Ok(response
        .stat
        .into_iter()
        .map(|stat| (stat.name, stat.value))
        .collect())
}

#[tokio::test]
async fn v2ray_stats_tracks_uuid_user_resets_and_restarts_on_sighup() {
    let Some(binary) = sing_box_binary() else {
        eprintln!("skipped V2Ray Stats E2E: sing-box binary unavailable");
        return;
    };
    let version = Command::new(&binary).arg("version").output().await.unwrap();
    if !String::from_utf8_lossy(&version.stdout).contains("with_v2ray_api") {
        eprintln!("skipped V2Ray Stats E2E: binary lacks with_v2ray_api");
        return;
    }
    if Command::new("curl")
        .arg("--version")
        .output()
        .await
        .is_err()
    {
        eprintln!("skipped V2Ray Stats E2E: curl unavailable");
        return;
    }

    let mut reserved = Vec::new();
    for port in 18120..=18129 {
        if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            reserved.push((port, listener));
            if reserved.len() == 3 {
                break;
            }
        }
    }
    assert_eq!(
        reserved.len(),
        3,
        "need three available loopback ports in 18120-18129"
    );
    let api_port = reserved[0].0;
    let proxy_port = reserved[1].0;
    let target_port = reserved[2].0;
    let target_listener = reserved.pop().unwrap().1;
    drop(reserved);
    target_listener.set_nonblocking(true).unwrap();
    let stopping = Arc::new(AtomicBool::new(false));
    let thread_stopping = stopping.clone();
    let server = thread::spawn(move || {
        while !thread_stopping.load(Ordering::Relaxed) {
            match target_listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0_u8; 2048];
                    let _ = stream.read(&mut request);
                    let body = b"counted-user-traffic";
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(body);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let user_id = Uuid::new_v4();
    let directory = tempdir().unwrap();
    let config_path = directory.path().join("sing-box.json");
    let config = json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed", "tag": "mixed-e2e", "listen": "127.0.0.1", "listen_port": proxy_port,
            "users": [{"username": user_id.to_string(), "password": "traffic-test-password"}]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "experimental": {"v2ray_api": {
            "listen": format!("127.0.0.1:{api_port}"),
            "stats": {"enabled": true, "users": [user_id.to_string()]}
        }}
    });
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let check = Command::new(&binary)
        .args(["check", "-c"])
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .unwrap();
    assert!(
        check.success(),
        "handwritten UUID user config must pass sing-box check"
    );
    drop(std::net::TcpListener::bind(("127.0.0.1", proxy_port)).unwrap());
    drop(std::net::TcpListener::bind(("127.0.0.1", api_port)).unwrap());

    let mut child = Command::new(&binary)
        .args(["run", "-c"])
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let endpoint = format!("http://127.0.0.1:{api_port}");
    let mut ready = false;
    for _ in 0..50 {
        if stats(&endpoint).await.is_ok() {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "V2Ray StatsService should listen on loopback");

    let response = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--socks5-hostname",
            &format!("127.0.0.1:{proxy_port}"),
            "-U",
            &format!("{user_id}:traffic-test-password"),
            &format!("http://127.0.0.1:{target_port}/"),
        ])
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(
        response.status.success(),
        "proxy request failed: {}",
        String::from_utf8_lossy(&response.stderr)
    );
    let first = stats(&endpoint).await.unwrap();
    let prefix = format!("user>>>{user_id}>>>traffic>>>");
    let uplink = first
        .iter()
        .find(|(name, _)| name == &(prefix.clone() + "uplink"))
        .unwrap()
        .1;
    let downlink = first
        .iter()
        .find(|(name, _)| name == &(prefix.clone() + "downlink"))
        .unwrap()
        .1;
    assert!(
        uplink > 0 && downlink > 0,
        "expected non-zero per-user up/down counters, got {first:?}"
    );
    let reset = stats(&endpoint).await.unwrap();
    assert!(
        reset.iter().all(|(_, value)| *value == 0),
        "reset query should clear counters: {reset:?}"
    );

    let response = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--socks5-hostname",
            &format!("127.0.0.1:{proxy_port}"),
            "-U",
            &format!("{user_id}:traffic-test-password"),
            &format!("http://127.0.0.1:{target_port}/"),
        ])
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(response.status.success());
    let pid = child.id().unwrap() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    sleep(Duration::from_millis(500)).await;
    let mut reset_after_reload = false;
    for _ in 0..50 {
        if let Ok(values) = stats(&endpoint).await {
            if values.iter().all(|(_, value)| *value == 0) {
                reset_after_reload = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        reset_after_reload,
        "SIGHUP should reset per-user stats to zero"
    );
    child.kill().await.unwrap();
    stopping.store(true, Ordering::Relaxed);
    server.join().unwrap();
}
