//! Persistent operation evidence is rechecked before ordinary vehicle access.
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
fn root_slot() -> &'static Mutex<Option<PathBuf>> {
    static ROOT: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
    ROOT.get_or_init(|| Mutex::new(None))
}
pub(crate) fn initialize(root: &Path) -> Result<Value, String> {
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let mut slot = root_slot()
        .lock()
        .map_err(|_| "Startup safety lock poisoned")?;
    if slot.as_ref().is_some_and(|previous| previous != &root) {
        return Err("Startup safety directory cannot change during this process".into());
    }
    *slot = Some(root.clone());
    drop(slot);
    Ok(review(&root))
}
fn review(root: &Path) -> Value {
    match crate::n20_operation_history::startup_review(root) {
        Ok(report) => report,
        Err(error) => {
            json!({"schema":"vehicle-startup-safety-v1","blocked":true,"detail":format!("Saved operation inspection failed: {error}"),"operations":[]})
        }
    }
}
pub(crate) fn storage_root() -> Result<PathBuf, String> {
    root_slot().lock().map_err(|_| "Startup safety lock poisoned")?
        .clone().ok_or_else(|| "Startup safety has not been initialized".into())
}
pub(crate) fn require_clear() -> Result<(), String> {
    let root = root_slot()
        .lock()
        .map_err(|_| "Startup safety lock poisoned")?
        .clone()
        .ok_or("Startup safety has not been initialized; vehicle access is paused")?;
    let report = review(&root);
    if report["blocked"] != false {
        return Err(format!(
            "Vehicle access paused: {}. Review saved flash/recovery evidence before reconnecting",
            report["detail"]
                .as_str()
                .unwrap_or("uncertain saved operation")
        ));
    }
    Ok(())
}
