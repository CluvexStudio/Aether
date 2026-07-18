# Data Directory Flag (`--data-dir` / `-d`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a `--data-dir` / `-d` CLI flag and `AETHER_DATA_DIR` environment variable to allow specifying a single base directory for all identity and session cache files.

**Architecture:** Add `-d, --data-dir` to CLI argument parsing in `cli.rs` setting `AETHER_DATA_DIR`. Create a path resolution helper function `resolve_config_path` in `cli.rs` (or `main.rs`) to resolve relative/default config paths under `AETHER_DATA_DIR` while allowing absolute path overrides. Ensure directory creation in `config::save` and `lastconn::save`.

**Tech Stack:** Rust, `std::path::Path`, `std::env`, Cargo.

## Global Constraints

- Flag name: `-d <dir>`, `--data-dir <dir>`
- Env Var: `AETHER_DATA_DIR`
- Relative paths for `--config`, `--wg-config`, `--masque-config` resolve relative to `--data-dir`.
- Absolute paths override `--data-dir`.
- Missing parent directories created automatically on save.

---

### Task 1: Parent Directory Creation in Config & Lastconn Persistence

**Files:**
- Modify: [`aether/src/config.rs:90-96`](file:///Users/vonar/src/Aether/aether/src/config.rs#L90-L96)
- Modify: [`aether/src/lastconn.rs:15-28`](file:///Users/vonar/src/Aether/aether/src/lastconn.rs#L15-L28)

**Interfaces:**
- Consumes: Existing `config::save` and `lastconn::save` functions.
- Produces: Safe writing to paths inside newly specified non-existent parent directories.

- [ ] **Step 1: Write failing unit tests for saving into non-existent directories**

Add unit tests to `aether/src/config.rs` and `aether/src/lastconn.rs`:

In `aether/src/config.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_save_creates_parent_dir() {
        let dir = tempdir().unwrap();
        let nested_path = dir.path().join("nested").join("dir").join("aether.toml");
        let path_str = nested_path.to_str().unwrap();

        let identity = Identity {
            device_id: "dev123".into(),
            access_token: "tok123".into(),
            cert_pem: vec![],
            key_pem: vec![],
            ipv4: "192.0.2.1".into(),
            ipv6: "2001:db8::1".into(),
            wg_private_key: [1u8; 32],
            wg_peer_public_key: [2u8; 32],
            client_id: [0u8; 3],
        };

        save(path_str, &identity).unwrap();
        assert!(nested_path.exists());
    }
}
```

In `aether/src/lastconn.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_lastconn_save_creates_parent_dir() {
        let dir = tempdir().unwrap();
        let nested_path = dir.path().join("nested").join("dir").join("lastconn.toml");
        let path_str = nested_path.to_str().unwrap();

        save(path_str, "127.0.0.1:443", "firewall");
        assert!(nested_path.exists());
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test --manifest-path aether/Cargo.toml`
Expected: FAIL due to missing parent directory when writing file.

- [ ] **Step 3: Implement parent directory creation**

In `aether/src/config.rs`:
```rust
pub fn save(path: &str, identity: &Identity) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let persisted = PersistedIdentity::from(identity);
    let text = toml::to_string_pretty(&persisted)
        .map_err(|e| AetherError::Other(format!("config encode: {e}")))?;
    std::fs::write(path, text)?;
    Ok(())
}
```

In `aether/src/lastconn.rs`:
```rust
pub fn save(path: &str, peer: &str, profile: &str) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let conn = LastConnection {
        peer: peer.to_string(),
        profile: profile.to_string(),
    };
    match toml::to_string_pretty(&conn) {
        Ok(text) => {
            if let Err(e) = std::fs::write(path, text) {
                log::debug!("[lastconn] failed to save {path}: {e}");
            }
        }
        Err(e) => log::debug!("[lastconn] failed to encode: {e}"),
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --manifest-path aether/Cargo.toml`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add aether/src/config.rs aether/src/lastconn.rs
git commit -m "feat: create parent directories automatically in config and lastconn save"
```

---

### Task 2: Config Path Resolution Helper & Unit Tests

**Files:**
- Modify: [`aether/src/cli.rs`](file:///Users/vonar/src/Aether/aether/src/cli.rs)

**Interfaces:**
- Produces: `pub fn resolve_config_path(data_dir: Option<&str>, explicit_path: Option<&str>, default_filename: &str) -> String`

- [ ] **Step 1: Write failing unit test for `resolve_config_path`**

Add unit tests at the end of `aether/src/cli.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_config_path_no_data_dir() {
        assert_eq!(resolve_config_path(None, None, "aether.toml"), "aether.toml");
        assert_eq!(resolve_config_path(None, Some("custom.toml"), "aether.toml"), "custom.toml");
        assert_eq!(resolve_config_path(None, Some("/abs/path.toml"), "aether.toml"), "/abs/path.toml");
    }

    #[test]
    fn test_resolve_config_path_with_data_dir() {
        assert_eq!(
            resolve_config_path(Some("/var/lib/aether"), None, "aether.toml"),
            format!("{}/aether.toml", std::path::Path::new("/var/lib/aether").display())
        );
        assert_eq!(
            resolve_config_path(Some("/var/lib/aether"), Some("custom.toml"), "aether.toml"),
            format!("{}/custom.toml", std::path::Path::new("/var/lib/aether").display())
        );
        assert_eq!(
            resolve_config_path(Some("/var/lib/aether"), Some("/abs/path.toml"), "aether.toml"),
            "/abs/path.toml"
        );
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test --manifest-path aether/Cargo.toml`
Expected: FAIL with "cannot find function `resolve_config_path` in this scope"

- [ ] **Step 3: Implement `resolve_config_path`**

In `aether/src/cli.rs`:

```rust
pub fn resolve_config_path(
    data_dir: Option<&str>,
    explicit_path: Option<&str>,
    default_filename: &str,
) -> String {
    match explicit_path {
        Some(path) => {
            let p = std::path::Path::new(path);
            if p.is_absolute() {
                path.to_string()
            } else if let Some(dir) = data_dir {
                std::path::Path::new(dir)
                    .join(path)
                    .to_string_lossy()
                    .to_string()
            } else {
                path.to_string()
            }
        }
        None => match data_dir {
            Some(dir) => std::path::Path::new(dir)
                .join(default_filename)
                .to_string_lossy()
                .to_string(),
            None => default_filename.to_string(),
        },
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --manifest-path aether/Cargo.toml`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add aether/src/cli.rs
git commit -m "feat: add resolve_config_path helper function"
```

---

### Task 3: CLI Argument Parsing for `-d` / `--data-dir`

**Files:**
- Modify: [`aether/src/cli.rs`](file:///Users/vonar/src/Aether/aether/src/cli.rs)

**Interfaces:**
- Consumes: Command line arguments.
- Produces: Sets environment variable `AETHER_DATA_DIR` when `-d` or `--data-dir` is passed.

- [ ] **Step 1: Write failing unit test for `-d` / `--data-dir` argument parsing**

Add unit test to `aether/src/cli.rs`:

```rust
#[test]
fn test_cli_parse_data_dir() {
    // Test logic invoking argument parsing behavior
    std::env::remove_var("AETHER_DATA_DIR");
    parse_args_from(vec!["aether".to_string(), "-d".to_string(), "/tmp/aether-data".to_string()]).unwrap();
    assert_eq!(std::env::var("AETHER_DATA_DIR").unwrap(), "/tmp/aether-data");

    std::env::remove_var("AETHER_DATA_DIR");
    parse_args_from(vec!["aether".to_string(), "--data-dir".to_string(), "/tmp/aether-data-2".to_string()]).unwrap();
    assert_eq!(std::env::var("AETHER_DATA_DIR").unwrap(), "/tmp/aether-data-2");
}
```

(Refactor `parse_and_apply()` to delegate to `parse_args_from(args: Vec<String>)`).

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test --manifest-path aether/Cargo.toml`
Expected: FAIL with "unknown option '-d'"

- [ ] **Step 3: Implement `-d` / `--data-dir` handling in `cli.rs`**

Update `USAGE` string in `aether/src/cli.rs`:
```rust
Config files:
  -d, --data-dir <dir>     base directory for identity and session files
  --config <path>          base identity config path (default aether.toml)
  --wg-config <path>       identity config path for WireGuard
  --masque-config <path>   identity config path for MASQUE
```

Update `parse_and_apply` / `parse_args_from` match block in `aether/src/cli.rs`:
```rust
"-d" | "--data-dir" => set("AETHER_DATA_DIR", next_value!()),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --manifest-path aether/Cargo.toml`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add aether/src/cli.rs
git commit -m "feat: add -d and --data-dir CLI flags"
```

---

### Task 4: Integration in `main.rs` Config Path Resolution

**Files:**
- Modify: [`aether/src/main.rs:55,136-148`](file:///Users/vonar/src/Aether/aether/src/main.rs#L55)

**Interfaces:**
- Consumes: `cli::resolve_config_path`, `AETHER_DATA_DIR`, `AETHER_CONFIG`, `AETHER_WG_CONFIG`, `AETHER_MASQUE_CONFIG`.
- Produces: Properly resolved paths for base identity, WireGuard identity, and MASQUE identity configs.

- [ ] **Step 1: Write integration test verifying path resolution in main config functions**

Add integration test module in `aether/src/main.rs` (or test module):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main_config_path_resolution_with_data_dir() {
        let data_dir = "/custom/data/dir";
        let resolved_base = cli::resolve_config_path(
            Some(data_dir),
            std::env::var("AETHER_CONFIG").ok().as_deref(),
            DEFAULT_CONFIG,
        );
        assert_eq!(resolved_base, "/custom/data/dir/aether.toml");

        let resolved_wg = cli::resolve_config_path(
            Some(data_dir),
            std::env::var("AETHER_WG_CONFIG").ok().as_deref(),
            &resolved_base,
        );
        assert_eq!(resolved_wg, "/custom/data/dir/aether.toml");

        let resolved_masque = masque_config_path_resolved(Some(data_dir), &resolved_base);
        assert_eq!(resolved_masque, "/custom/data/dir/aether-masque.toml");
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test --manifest-path aether/Cargo.toml`
Expected: FAIL because `main.rs` does not yet use `cli::resolve_config_path` and `masque_config_path_resolved`.

- [ ] **Step 3: Update `main.rs` config path functions**

In `aether/src/main.rs`:

```rust
    let data_dir = std::env::var("AETHER_DATA_DIR").ok();
    let base_config = cli::resolve_config_path(
        data_dir.as_deref(),
        std::env::var("AETHER_CONFIG").ok().as_deref(),
        DEFAULT_CONFIG,
    );
```

Update `warp_config_path` and `masque_config_path`:

```rust
fn warp_config_path(base: &str) -> String {
    let data_dir = std::env::var("AETHER_DATA_DIR").ok();
    cli::resolve_config_path(
        data_dir.as_deref(),
        std::env::var("AETHER_WG_CONFIG").ok().as_deref(),
        base,
    )
}

fn masque_config_path(base: &str) -> String {
    let data_dir = std::env::var("AETHER_DATA_DIR").ok();
    if let Ok(p) = std::env::var("AETHER_MASQUE_CONFIG") {
        return cli::resolve_config_path(data_dir.as_deref(), Some(&p), base);
    }
    derive_sibling_path(base, "masque")
}
```

- [ ] **Step 4: Run tests to verify all tests pass**

Run: `cargo test --manifest-path aether/Cargo.toml`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add aether/src/main.rs
git commit -m "feat: apply AETHER_DATA_DIR to config path resolution in main.rs"
```

---

### Task 5: Documentation Updates

**Files:**
- Modify: [`Docs/GUIDE.en.md`](file:///Users/vonar/src/Aether/Docs/GUIDE.en.md)
- Modify: [`Docs/GUIDE.fa.md`](file:///Users/vonar/src/Aether/Docs/GUIDE.fa.md)

- [ ] **Step 1: Update English documentation (`Docs/GUIDE.en.md`)**

Add `AETHER_DATA_DIR` and `-d, --data-dir` under CLI flags and environment variables sections:
```markdown
- `AETHER_DATA_DIR` (`-d`, `--data-dir`) — the base directory for storing identity configs and last-connection state files.
```

- [ ] **Step 2: Update Persian documentation (`Docs/GUIDE.fa.md`)**

Add `AETHER_DATA_DIR` and `-d, --data-dir` under CLI flags and environment variables sections in Persian guide.

- [ ] **Step 3: Run full build and tests to verify everything is clean**

Run: `cargo check --manifest-path aether/Cargo.toml`
Expected: Clean build without errors or warnings.

- [ ] **Step 4: Commit documentation changes**

```bash
git add Docs/GUIDE.en.md Docs/GUIDE.fa.md
git commit -m "docs: document -d/--data-dir flag and AETHER_DATA_DIR environment variable"
```
