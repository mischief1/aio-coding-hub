mod support;

use serde_json::json;

#[test]
fn mcp_import_from_workspace_cli_reads_claude_json_and_imports() {
    let app = support::TestApp::new();
    let handle = app.handle();

    let source = json!({
      "mcpServers": {
        "fetch": {
          "type": "stdio",
          "command": "uvx",
          "args": ["mcp-server-fetch"],
          "env": {"FOO": "bar"},
          "cwd": "/tmp/project"
        }
      }
    });

    let bytes = serde_json::to_vec(&source).expect("json bytes");
    aio_coding_hub_lib::test_support::mcp_restore_target_bytes(&handle, "claude", Some(bytes))
        .expect("write claude target");

    let workspace_id =
        aio_coding_hub_lib::test_support::workspace_active_id_by_cli(&handle, "claude")
            .expect("claude active workspace");

    let report =
        aio_coding_hub_lib::test_support::mcp_import_from_workspace_cli_json(&handle, workspace_id)
            .expect("import from workspace cli");

    assert_eq!(report.get("inserted").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(report.get("updated").and_then(|v| v.as_u64()), Some(0));

    let rows = aio_coding_hub_lib::test_support::mcp_servers_list_json(&handle, workspace_id)
        .expect("list imported rows");
    let rows = rows.as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1);

    let first = &rows[0];
    assert_eq!(first.get("name").and_then(|v| v.as_str()), Some("fetch"));
    assert_eq!(
        first.get("transport").and_then(|v| v.as_str()),
        Some("stdio")
    );
    assert_eq!(first.get("command").and_then(|v| v.as_str()), Some("uvx"));
    assert_eq!(first.get("enabled").and_then(|v| v.as_bool()), Some(true));
}

#[test]
fn mcp_import_from_workspace_cli_parses_codex_toml() {
    let app = support::TestApp::new();
    let handle = app.handle();

    let codex_toml = r#"
[mcp_servers.fetch]
type = "stdio"
command = "uvx"
args = ["mcp-server-fetch"]
cwd = "/tmp/workspace"

[mcp_servers.fetch.env]
FOO = "bar"
"#;

    aio_coding_hub_lib::test_support::mcp_restore_target_bytes(
        &handle,
        "codex",
        Some(codex_toml.as_bytes().to_vec()),
    )
    .expect("write codex target");

    let workspace_id =
        aio_coding_hub_lib::test_support::workspace_active_id_by_cli(&handle, "codex")
            .expect("codex active workspace");

    let report =
        aio_coding_hub_lib::test_support::mcp_import_from_workspace_cli_json(&handle, workspace_id)
            .expect("import codex target");

    assert_eq!(report.get("inserted").and_then(|v| v.as_u64()), Some(1));

    let rows = aio_coding_hub_lib::test_support::mcp_servers_list_json(&handle, workspace_id)
        .expect("list imported rows");
    let rows = rows.as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("command").and_then(|v| v.as_str()), Some("uvx"));
}

#[test]
fn mcp_import_from_workspace_cli_preserves_server_key_casing() {
    let app = support::TestApp::new();
    let handle = app.handle();

    let source = json!({
      "mcpServers": {
        "AMap": {
          "type": "stdio",
          "command": "node",
          "args": ["D:/tools/mcp/amap-maps/start.mjs"],
          "env": {"AMAP_MAPS_API_KEY": "xxx"}
        }
      }
    });

    let bytes = serde_json::to_vec(&source).expect("json bytes");
    aio_coding_hub_lib::test_support::mcp_restore_target_bytes(&handle, "claude", Some(bytes))
        .expect("write claude target");

    let workspace_id =
        aio_coding_hub_lib::test_support::workspace_active_id_by_cli(&handle, "claude")
            .expect("claude active workspace");

    let report =
        aio_coding_hub_lib::test_support::mcp_import_from_workspace_cli_json(&handle, workspace_id)
            .expect("import from workspace cli");

    assert_eq!(report.get("inserted").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(report.get("updated").and_then(|v| v.as_u64()), Some(0));

    let rows = aio_coding_hub_lib::test_support::mcp_servers_list_json(&handle, workspace_id)
        .expect("list imported rows");
    let rows = rows.as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("server_key").and_then(|v| v.as_str()),
        Some("AMap")
    );

    let synced = aio_coding_hub_lib::test_support::mcp_read_target_bytes(&handle, "claude")
        .expect("read synced claude target")
        .expect("synced claude target must exist");
    let root: serde_json::Value = serde_json::from_slice(&synced).expect("parse synced json");
    let servers = root
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .expect("mcpServers object");
    assert!(servers.contains_key("AMap"));
    assert!(!servers.contains_key("amap"));
}
