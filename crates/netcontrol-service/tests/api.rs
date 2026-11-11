use netcontrol_core::config::{Config, Paths};
use netcontrol_core::models::{HostObservation, Role};
use netcontrol_core::security;
use netcontrol_service::{api, AppState};
use std::net::SocketAddr;

#[tokio::test]
async fn auth_scope_guard_and_unverified_enforcement_contract() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under_root(dir.path().to_path_buf());
    let state = AppState::load(paths, Config::default()).unwrap();
    let hash = security::hash_password("NetControl!2026").unwrap();
    state.db.create_user("admin", &hash, Role::Admin).unwrap();

    let mut observation = HostObservation::new("192.168.1.50", "test");
    observation.mac = Some("aa:bb:cc:dd:ee:50".into());
    observation.hostname = Some("test-device".into());
    let device = state
        .db
        .upsert_observation(&observation, Some("eth0"), None, "test-scan")
        .unwrap()
        .device;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let app = api::router(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let base = format!("http://{addr}/api/v1");
    let client = reqwest::Client::new();
    assert!(client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    assert_eq!(
        client
            .get(format!("{base}/dashboard"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    let login = client
        .post(format!("{base}/auth/login"))
        .json(&serde_json::json!({"username":"admin","password":"NetControl!2026"}))
        .send()
        .await
        .unwrap();
    assert!(login.status().is_success());
    let session: serde_json::Value = login.json().await.unwrap();
    let token = session["token"].as_str().unwrap().to_string();

    let unauth_scan = client
        .post(format!("{base}/scans"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"confirm":false}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_scan.status(), reqwest::StatusCode::BAD_REQUEST);

    let response = client
        .post(format!("{base}/devices/{}/block", device.id))
        .bearer_auth(&token)
        .json(&serde_json::json!({"confirm":true,"reason":"test"}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["result"]["verified"], false);
    assert_eq!(body["result"]["action"], "unsupported");
    assert_eq!(body["device"]["is_blocked"], false);
    assert_eq!(body["device"]["enforcement"], "unsupported");

    let stored = state.db.get_device(&device.id).unwrap().unwrap();
    assert!(!stored.is_blocked);
    assert_eq!(
        stored.enforcement,
        netcontrol_core::models::EnforcementState::Unsupported
    );

    let audit = state.db.list_audit(10, 0).unwrap();
    assert!(audit
        .iter()
        .any(|entry| entry.action == "block" && entry.outcome == "unsupported"));

    server.abort();
}
