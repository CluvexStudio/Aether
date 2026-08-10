use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use futures::FutureExt;
use parking_lot::Mutex;
use serde_json::{json, Value};

use crate::account::Identity;
use crate::api;
use crate::zerotrust;

type Reply = std::result::Result<Value, String>;

fn runtime() -> Option<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .ok()
        })
        .as_ref()
}

fn next_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

enum JobState {
    Running,
    Done(Value),
}

struct Job {
    cancel: api::Cancel,
    state: Arc<Mutex<JobState>>,
}

fn jobs() -> &'static Mutex<HashMap<u64, Job>> {
    static JOBS: OnceLock<Mutex<HashMap<u64, Job>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn identities() -> &'static Mutex<HashMap<u64, Arc<Identity>>> {
    static IDENTITIES: OnceLock<Mutex<HashMap<u64, Arc<Identity>>>> = OnceLock::new();
    IDENTITIES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn sessions() -> &'static Mutex<HashMap<u64, Arc<tokio::sync::Mutex<zerotrust::EmailSignIn>>>> {
    static SESSIONS: OnceLock<
        Mutex<HashMap<u64, Arc<tokio::sync::Mutex<zerotrust::EmailSignIn>>>>,
    > = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn into_c_string(text: String) -> *mut c_char {
    match CString::new(text) {
        Ok(value) => value.into_raw(),
        Err(_) => CString::new("{\"ok\":false,\"error\":\"the reply held a null byte\"}")
            .expect("static reply")
            .into_raw(),
    }
}

fn ok_value(value: Value) -> Value {
    match value {
        Value::Object(mut fields) => {
            fields.insert("ok".to_string(), Value::Bool(true));
            Value::Object(fields)
        }
        other => json!({"ok": true, "result": other}),
    }
}

fn error_value(message: String) -> Value {
    json!({"ok": false, "error": message})
}

fn respond<F>(work: F) -> *mut c_char
where
    F: FnOnce() -> Reply,
{
    let value = match catch_unwind(AssertUnwindSafe(work)) {
        Ok(Ok(value)) => ok_value(value),
        Ok(Err(message)) => error_value(message),
        Err(_) => error_value("the core panicked".to_string()),
    };
    into_c_string(value.to_string())
}

unsafe fn read_str(raw: *const c_char) -> std::result::Result<String, String> {
    if raw.is_null() {
        return Err("a required argument was null".to_string());
    }
    CStr::from_ptr(raw)
        .to_str()
        .map(|value| value.to_string())
        .map_err(|_| "an argument was not valid utf-8".to_string())
}

unsafe fn read_json<T: serde::de::DeserializeOwned>(
    raw: *const c_char,
) -> std::result::Result<T, String> {
    let text = read_str(raw)?;
    serde_json::from_str(&text).map_err(|e| format!("the payload is not usable json: {e}"))
}

fn spawn_job<F, Fut>(work: F) -> Reply
where
    F: FnOnce(api::Cancel) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Reply> + Send,
{
    let runtime = runtime().ok_or_else(|| "could not start the async runtime".to_string())?;
    let cancel = api::Cancel::new();
    let state = Arc::new(Mutex::new(JobState::Running));
    let id = next_id();

    jobs().lock().insert(
        id,
        Job {
            cancel: cancel.clone(),
            state: state.clone(),
        },
    );

    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(work(cancel)).catch_unwind().await;
        let reply = match outcome {
            Ok(Ok(value)) => ok_value(value),
            Ok(Err(message)) => error_value(message),
            Err(_) => error_value("the core panicked".to_string()),
        };
        *state.lock() = JobState::Done(reply);
    });

    Ok(json!({"job": id}))
}

fn identity_of(id: u64) -> std::result::Result<Arc<Identity>, String> {
    identities()
        .lock()
        .get(&id)
        .cloned()
        .ok_or_else(|| format!("there is no identity {id}"))
}

fn session_of(
    id: u64,
) -> std::result::Result<Arc<tokio::sync::Mutex<zerotrust::EmailSignIn>>, String> {
    sessions()
        .lock()
        .get(&id)
        .cloned()
        .ok_or_else(|| format!("there is no sign-in session {id}"))
}

fn keep_identity(identity: Identity) -> Value {
    let summary = api::IdentitySummary::of(&identity);
    let id = next_id();
    identities().lock().insert(id, Arc::new(identity));
    json!({"identity": id, "summary": summary})
}

fn describe(error: crate::error::AetherError) -> String {
    error.to_string()
}

#[derive(serde::Deserialize)]
struct TeamPayload {
    team: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

impl TeamPayload {
    fn credentials(&self) -> std::result::Result<api::TeamCredentials, String> {
        let mut credentials = api::TeamCredentials::new(&self.team).map_err(describe)?;
        credentials.client_id = self.client_id.clone();
        credentials.client_secret = self.client_secret.clone();
        credentials.token = self.token.clone();
        credentials.email = self.email.clone();
        Ok(credentials)
    }
}

#[derive(serde::Deserialize)]
struct OpenPayload {
    path: String,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    locale: Option<String>,
    #[serde(default)]
    team: Option<TeamPayload>,
}

#[derive(serde::Deserialize)]
struct ScanPayload {
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    ports: Option<Vec<u16>>,
    #[serde(default)]
    excluded: Option<Vec<String>>,
    #[serde(default)]
    ech: Option<bool>,
}

#[derive(serde::Deserialize)]
struct TunnelPayload {
    peer: String,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    socks: Option<String>,
    #[serde(default)]
    http: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    keepalive: Option<u16>,
    #[serde(default)]
    ech: Option<bool>,
}

fn transport_of(raw: &Option<String>) -> api::Transport {
    match raw {
        Some(value) => api::Transport::parse(value),
        None => api::Transport::Masque,
    }
}

fn socket_of(raw: &str, label: &str) -> std::result::Result<SocketAddr, String> {
    raw.trim()
        .parse()
        .map_err(|_| format!("{label} '{raw}' is not an address:port"))
}

#[no_mangle]
pub extern "C" fn aether_version() -> *mut c_char {
    respond(|| Ok(json!({"version": env!("CARGO_PKG_VERSION")})))
}

#[no_mangle]
pub extern "C" fn aether_string_free(raw: *mut c_char) {
    if raw.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(CString::from_raw(raw));
    }));
}

#[no_mangle]
pub extern "C" fn aether_job_poll(id: u64) -> *mut c_char {
    respond(|| {
        let registry = jobs().lock();
        let job = registry
            .get(&id)
            .ok_or_else(|| format!("there is no job {id}"))?;
        let state = job.state.lock();
        match &*state {
            JobState::Running => Ok(json!({"state": "running"})),
            JobState::Done(result) => Ok(json!({"state": "done", "result": result})),
        }
    })
}

#[no_mangle]
pub extern "C" fn aether_job_cancel(id: u64) -> *mut c_char {
    respond(|| {
        let registry = jobs().lock();
        let job = registry
            .get(&id)
            .ok_or_else(|| format!("there is no job {id}"))?;
        job.cancel.cancel();
        Ok(json!({"cancelled": id}))
    })
}

#[no_mangle]
pub extern "C" fn aether_job_free(id: u64) -> *mut c_char {
    respond(|| {
        let removed = jobs().lock().remove(&id);
        match removed {
            Some(job) => {
                job.cancel.cancel();
                Ok(json!({"freed": id}))
            }
            None => Ok(json!({"freed": Value::Null})),
        }
    })
}

#[no_mangle]
pub extern "C" fn aether_identity_open(payload: *const c_char) -> *mut c_char {
    respond(|| {
        let payload: OpenPayload = unsafe { read_json(payload) }?;
        let transport = transport_of(&payload.transport);

        let mut request = api::ProvisionRequest::for_transport(transport);
        if let Some(model) = payload.model {
            request.model = model;
        }
        if let Some(locale) = payload.locale {
            request.locale = locale;
        }

        let team = match &payload.team {
            Some(team) => Some(team.credentials()?),
            None => None,
        };
        let team_name = team.as_ref().map(|team| team.team.clone());
        request.team = team;

        let path = api::identity_path(&payload.path, transport, team_name.as_deref());

        spawn_job(move |_| async move {
            let identity = api::open_identity(&path, &request).await.map_err(describe)?;
            let mut reply = keep_identity(identity);
            if let Value::Object(fields) = &mut reply {
                fields.insert("path".to_string(), Value::String(path.clone()));
                fields.insert(
                    "lastconn_path".to_string(),
                    Value::String(api::lastconn_path(&path)),
                );
            }
            Ok(reply)
        })
    })
}

#[no_mangle]
pub extern "C" fn aether_identity_summary(id: u64) -> *mut c_char {
    respond(|| {
        let identity = identity_of(id)?;
        Ok(json!({"summary": api::IdentitySummary::of(&identity)}))
    })
}

#[no_mangle]
pub extern "C" fn aether_identity_free(id: u64) -> *mut c_char {
    respond(|| {
        identities().lock().remove(&id);
        Ok(json!({"freed": id}))
    })
}

#[no_mangle]
pub extern "C" fn aether_scan_start(identity: u64, payload: *const c_char) -> *mut c_char {
    respond(|| {
        let payload: ScanPayload = unsafe { read_json(payload) }?;
        let identity = identity_of(identity)?;
        let transport = transport_of(&payload.transport);

        let mut request = api::ScanRequest::for_transport(transport);
        if let Some(profile) = &payload.profile {
            request = request.with_profile(profile);
        }
        if let Some(mode) = &payload.mode {
            request.mode = mode.clone();
        }
        if let Some(ip) = &payload.ip {
            request.ip = crate::prober::IpScan::parse(ip);
        }
        if let Some(ports) = payload.ports {
            if !ports.is_empty() {
                request.ports = ports;
            }
        }
        if let Some(excluded) = payload.excluded {
            for raw in excluded {
                if let Ok(address) = raw.trim().parse::<SocketAddr>() {
                    request.excluded.insert(address);
                }
            }
        }

        let want_ech = payload.ech.unwrap_or(false);

        spawn_job(move |cancel| async move {
            let mut request = request;
            if want_ech {
                request.ech_config_list = api::fetch_ech_config().await;
            }
            let endpoint = api::scan(&identity, &request, &cancel)
                .await
                .map_err(describe)?;
            Ok(json!({"endpoint": endpoint}))
        })
    })
}

fn tunnel_spec_of(payload: &TunnelPayload) -> std::result::Result<api::TunnelSpec, String> {
    let transport = transport_of(&payload.transport);
    let mut spec = api::TunnelSpec::for_transport(transport);

    if let Some(profile) = &payload.profile {
        spec = spec.with_profile(profile);
    }
    if let Some(socks) = &payload.socks {
        spec.socks = socket_of(socks, "the socks address")?;
    }
    if let Some(http) = &payload.http {
        spec.http = Some(socket_of(http, "the http proxy address")?);
    }
    if let Some(keepalive) = payload.keepalive {
        spec.keepalive = keepalive;
    }
    Ok(spec)
}

#[no_mangle]
pub extern "C" fn aether_verify_start(identity: u64, payload: *const c_char) -> *mut c_char {
    respond(|| {
        let payload: TunnelPayload = unsafe { read_json(payload) }?;
        let identity = identity_of(identity)?;
        let peer = socket_of(&payload.peer, "the peer address")?;
        let spec = tunnel_spec_of(&payload)?;

        spawn_job(move |cancel| async move {
            let reachable = api::verify_endpoint(&identity, peer, &spec, &cancel)
                .await
                .map_err(describe)?;
            Ok(json!({"reachable": reachable}))
        })
    })
}

#[no_mangle]
pub extern "C" fn aether_tunnel_start(identity: u64, payload: *const c_char) -> *mut c_char {
    respond(|| {
        let payload: TunnelPayload = unsafe { read_json(payload) }?;
        let identity = identity_of(identity)?;
        let peer = socket_of(&payload.peer, "the peer address")?;
        let spec = tunnel_spec_of(&payload)?;
        let want_ech = payload.ech.unwrap_or(false);

        spawn_job(move |cancel| async move {
            let mut spec = spec;
            if want_ech && matches!(spec.transport, api::Transport::Masque) {
                spec.ech = api::fetch_ech_config().await;
            }

            match api::connect(&identity, peer, &spec, &cancel).await {
                Ok(()) => Ok(json!({"state": "closed"})),
                Err(crate::error::AetherError::Cancelled) => Ok(json!({"state": "stopped"})),
                Err(e) => Err(describe(e)),
            }
        })
    })
}

#[no_mangle]
pub extern "C" fn aether_core_start(arguments: *const c_char) -> *mut c_char {
    respond(|| {
        let arguments: Vec<String> = if arguments.is_null() {
            Vec::new()
        } else {
            let text = unsafe { read_str(arguments) }?;
            match text.trim().is_empty() {
                true => Vec::new(),
                false => serde_json::from_str(&text)
                    .map_err(|e| format!("the argument list is not a json array of strings: {e}"))?,
            }
        };

        spawn_job(move |cancel| async move {
            let attempt = crate::run_with(arguments);
            tokio::select! {
                biased;
                _ = cancel.wait() => Ok(json!({"state": "stopped"})),
                outcome = attempt => match outcome {
                    Ok(()) => Ok(json!({"state": "closed"})),
                    Err(e) => Err(describe(e)),
                },
            }
        })
    })
}

#[no_mangle]
pub extern "C" fn aether_team_sign_in(payload: *const c_char) -> *mut c_char {
    respond(|| {
        let payload: TeamPayload = unsafe { read_json(payload) }?;
        let credentials = payload.credentials()?;

        spawn_job(move |_| async move {
            let token = api::team_sign_in(&credentials).await.map_err(describe)?;
            Ok(json!({"token": token}))
        })
    })
}

#[no_mangle]
pub extern "C" fn aether_team_code_request(payload: *const c_char) -> *mut c_char {
    respond(|| {
        let payload: TeamPayload = unsafe { read_json(payload) }?;
        let email = payload
            .email
            .clone()
            .ok_or_else(|| "an email address is needed to request a login code".to_string())?;
        let credentials = payload.credentials()?;

        spawn_job(move |_| async move {
            let session = api::team_email_code_request(&credentials, &email)
                .await
                .map_err(describe)?;
            let email = session.email().to_string();
            let id = next_id();
            sessions()
                .lock()
                .insert(id, Arc::new(tokio::sync::Mutex::new(session)));
            Ok(json!({"session": id, "email": email}))
        })
    })
}

#[no_mangle]
pub extern "C" fn aether_team_code_resend(session: u64) -> *mut c_char {
    respond(|| {
        let session = session_of(session)?;

        spawn_job(move |_| async move {
            let mut guard = session.lock().await;
            api::team_email_code_resend(&mut guard)
                .await
                .map_err(describe)?;
            Ok(json!({"sent": true}))
        })
    })
}

#[no_mangle]
pub extern "C" fn aether_team_code_submit(session: u64, code: *const c_char) -> *mut c_char {
    respond(|| {
        let code = unsafe { read_str(code) }?;
        let session = session_of(session)?;

        spawn_job(move |_| async move {
            let guard = session.lock().await;
            let token = api::team_email_code_submit(&guard, &code)
                .await
                .map_err(describe)?;
            match token {
                Some(token) => Ok(json!({"signed_in": true, "token": token})),
                None => Ok(json!({"signed_in": false})),
            }
        })
    })
}

#[no_mangle]
pub extern "C" fn aether_team_session_free(id: u64) -> *mut c_char {
    respond(|| {
        sessions().lock().remove(&id);
        Ok(json!({"freed": id}))
    })
}

#[no_mangle]
pub extern "C" fn aether_team_token_set(token: *const c_char) -> *mut c_char {
    respond(|| {
        let token = unsafe { read_str(token) }?;
        let runtime = runtime().ok_or_else(|| "could not start the async runtime".to_string())?;
        runtime
            .block_on(api::team_use_token(&token))
            .map_err(describe)?;
        Ok(json!({"stored": true}))
    })
}

#[no_mangle]
pub extern "C" fn aether_team_token_clear() -> *mut c_char {
    respond(|| {
        let runtime = runtime().ok_or_else(|| "could not start the async runtime".to_string())?;
        runtime.block_on(api::team_forget_token());
        Ok(json!({"cleared": true}))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(raw: *mut c_char) -> Value {
        assert!(!raw.is_null(), "the reply pointer must not be null");
        let text = unsafe { CStr::from_ptr(raw) }
            .to_str()
            .expect("utf-8 reply")
            .to_string();
        aether_string_free(raw);
        serde_json::from_str(&text).expect("the reply must be json")
    }

    fn text_of(value: &str) -> CString {
        CString::new(value).expect("no null bytes")
    }

    #[test]
    fn the_version_comes_back_as_json() {
        let reply = take(aether_version());
        assert_eq!(reply["ok"], json!(true));
        assert_eq!(reply["version"], json!(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn freeing_a_null_string_is_harmless() {
        aether_string_free(std::ptr::null_mut());
    }

    #[test]
    fn a_null_payload_is_reported_instead_of_crashing() {
        let reply = take(aether_identity_open(std::ptr::null()));
        assert_eq!(reply["ok"], json!(false));
        assert!(reply["error"].as_str().unwrap().contains("null"));
    }

    #[test]
    fn a_payload_that_is_not_json_is_reported() {
        let payload = text_of("not json at all");
        let reply = take(aether_identity_open(payload.as_ptr()));
        assert_eq!(reply["ok"], json!(false));
        assert!(reply["error"].as_str().unwrap().contains("usable json"));
    }

    #[test]
    fn an_unknown_identity_is_reported() {
        let reply = take(aether_identity_summary(999_999));
        assert_eq!(reply["ok"], json!(false));
        assert!(reply["error"]
            .as_str()
            .unwrap()
            .contains("no identity 999999"));
    }

    #[test]
    fn an_unknown_job_is_reported() {
        let reply = take(aether_job_poll(999_999));
        assert_eq!(reply["ok"], json!(false));
        assert!(reply["error"].as_str().unwrap().contains("no job 999999"));
    }

    #[test]
    fn freeing_a_job_that_was_never_there_is_not_an_error() {
        let reply = take(aether_job_free(999_999));
        assert_eq!(reply["ok"], json!(true));
        assert_eq!(reply["freed"], Value::Null);
    }

    #[test]
    fn a_bad_team_name_is_rejected_before_any_request_is_made() {
        let payload = text_of("{\"team\":\"bad name!\"}");
        let reply = take(aether_team_sign_in(payload.as_ptr()));
        assert_eq!(reply["ok"], json!(false));
        assert!(reply["error"].as_str().unwrap().contains("not a usable"));
    }

    #[test]
    fn requesting_a_code_without_an_email_is_rejected() {
        let payload = text_of("{\"team\":\"acme\"}");
        let reply = take(aether_team_code_request(payload.as_ptr()));
        assert_eq!(reply["ok"], json!(false));
        assert!(reply["error"].as_str().unwrap().contains("email"));
    }

    #[test]
    fn a_token_that_is_not_a_jwt_is_refused() {
        let token = text_of("not-a-jwt");
        let reply = take(aether_team_token_set(token.as_ptr()));
        assert_eq!(reply["ok"], json!(false));
        assert!(reply["error"].as_str().unwrap().contains("jwt"));
    }

    #[test]
    fn a_job_runs_to_completion_and_can_be_polled() {
        let started = respond(|| spawn_job(|_| async { Ok(json!({"done": true})) }));
        let started = take(started);
        assert_eq!(started["ok"], json!(true));
        let id = started["job"].as_u64().expect("a job id");

        let mut result = Value::Null;
        for _ in 0..200 {
            let polled = take(aether_job_poll(id));
            if polled["state"] == json!("done") {
                result = polled["result"].clone();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["done"], json!(true));
        take(aether_job_free(id));
    }

    #[test]
    fn a_job_that_panics_is_reported_instead_of_hanging() {
        let started = take(respond(|| {
            spawn_job(|_| async { panic!("the job blew up") })
        }));
        let id = started["job"].as_u64().expect("a job id");

        let mut result = Value::Null;
        for _ in 0..200 {
            let polled = take(aether_job_poll(id));
            if polled["state"] == json!("done") {
                result = polled["result"].clone();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert_eq!(result["ok"], json!(false));
        assert_eq!(result["error"], json!("the core panicked"));
        take(aether_job_free(id));
    }

    #[test]
    fn a_cancelled_job_reports_that_it_was_cancelled() {
        let started = take(respond(|| {
            spawn_job(|cancel| async move {
                cancel.wait().await;
                Err("cancelled".to_string())
            })
        }));
        let id = started["job"].as_u64().expect("a job id");

        take(aether_job_cancel(id));

        let mut result = Value::Null;
        for _ in 0..200 {
            let polled = take(aether_job_poll(id));
            if polled["state"] == json!("done") {
                result = polled["result"].clone();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert_eq!(result["ok"], json!(false));
        assert_eq!(result["error"], json!("cancelled"));
        take(aether_job_free(id));
    }

    #[test]
    fn the_core_refuses_an_argument_list_that_is_not_a_json_array() {
        let payload = text_of("--socks 127.0.0.1:1819");
        let reply = take(aether_core_start(payload.as_ptr()));
        assert_eq!(reply["ok"], json!(false));
        assert!(reply["error"].as_str().unwrap().contains("json array"));
    }

    #[test]
    fn an_unparsable_socks_address_is_reported() {
        let payload = text_of("{\"peer\":\"1.2.3.4:443\",\"socks\":\"not-an-address\"}");
        let reply = take(aether_tunnel_start(1, payload.as_ptr()));
        assert_eq!(reply["ok"], json!(false));
    }

    #[test]
    fn an_unparsable_peer_is_reported() {
        let payload = text_of("{\"peer\":\"nonsense\"}");
        let reply = take(aether_verify_start(1, payload.as_ptr()));
        assert_eq!(reply["ok"], json!(false));
    }
}
