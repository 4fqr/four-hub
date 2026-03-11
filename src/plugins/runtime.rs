
use crate::{config::AppConfig, db::Finding};
use anyhow::Result;
use pyo3::prelude::*;
use std::{collections::HashMap, path::PathBuf};
use tracing::{error, info, warn};

pub struct PluginRuntime {
    plugins: HashMap<String, Py<PyModule>>,
}

impl PluginRuntime {
    pub async fn new(cfg: &AppConfig) -> Result<Self> {
        let dir = cfg.plugins_dir();
        let mut plugins = HashMap::new();

        if !dir.exists() {
            info!(dir = %dir.display(), "plugins dir does not exist – skipping");
            return Ok(Self { plugins });
        }

        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("py") {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                match load_plugin(&path).await {
                    Ok(m) => {
                        info!(plugin = %name, "loaded plugin");
                        plugins.insert(name, m);
                    }
                    Err(e) => warn!(plugin = %name, err = %e, "failed to load plugin"),
                }
            }
        }

        Ok(Self { plugins })
    }
    pub async fn fire_new_finding(&self, finding: &Finding) -> Result<()> {
        let fdict = finding_to_dict(finding);
        Python::with_gil(|py| {
            for (name, module) in &self.plugins {
                if let Ok(hook) = module.getattr(py, "on_new_finding") {
                    if let Err(e) = hook.call1(py, (fdict.clone(),)) {
                        error!(plugin = %name, err = %e, "on_new_finding error");
                    }
                }
            }
        });
        Ok(())
    }
    pub async fn fire_tool_finished(&self, job_id: &str, exit_code: i32) -> Result<()> {
        Python::with_gil(|py| {
            for (name, module) in &self.plugins {
                if let Ok(hook) = module.getattr(py, "on_tool_finished") {
                    if let Err(e) = hook.call1(py, (job_id, exit_code)) {
                        error!(plugin = %name, err = %e, "on_tool_finished error");
                    }
                }
            }
        });
        Ok(())
    }
}

async fn load_plugin(path: &PathBuf) -> Result<Py<PyModule>> {
    let code = tokio::fs::read_to_string(path).await?;
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("plugin")
        .to_string();
    let module = Python::with_gil(|py| -> Result<Py<PyModule>> {
        let m = PyModule::from_code_bound(py, &code, path.to_str().unwrap_or(""), &name)?;
        Ok(m.into())
    })?;
    Ok(module)
}

fn finding_to_dict(finding: &Finding) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("id".into(),          finding.id.clone());
    m.insert("tool".into(),        finding.tool.clone());
    m.insert("title".into(),       finding.title.clone());
    m.insert("description".into(), finding.description.clone());
    m.insert("severity".into(),    finding.severity.as_str().to_string());
    m.insert("created_at".into(),  finding.created_at.to_rfc3339());
    m
}
