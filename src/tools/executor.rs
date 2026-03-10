// ─── Four-Hub · tools/executor.rs ────────────────────────────────────────────
//! Async tool execution engine.  Each tool runs in a tokio task;
//! stdout/stderr lines are streamed into the event bus.

use crate::{
    db::{Database, ScanJob},
    plugins::runtime::PluginRuntime,
    tools::{parser, spec::ToolSpec},
    tui::app_state::{NotifLevel},
    tui::events::AppEvent,
};
use anyhow::{bail, Result};
use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    sync::mpsc,
};
use tracing::{error, info, warn};
use uuid::Uuid;

// ── A handle to a running job ─────────────────────────────────────────────────

struct JobHandle {
    child:   Child,
    spec:    ToolSpec,
    target:  String,
    output:  Vec<String>,
}

// ── ToolExecutor ─────────────────────────────────────────────────────────────

pub struct ToolExecutor {
    db:        Arc<Database>,
    registry:  crate::tools::registry::ToolRegistry,
    event_tx:  mpsc::UnboundedSender<AppEvent>,
    plugin_rt: Arc<PluginRuntime>,
    jobs:      DashMap<String, tokio::task::AbortHandle>,
}

impl ToolExecutor {
    pub fn new(
        db:        Arc<Database>,
        registry:  crate::tools::registry::ToolRegistry,
        event_tx:  mpsc::UnboundedSender<AppEvent>,
        plugin_rt: Arc<PluginRuntime>,
    ) -> Self {
        Self { db, registry, event_tx, plugin_rt, jobs: DashMap::new() }
    }

    /// Spawn a new tool process.  Returns the job UUID.
    pub async fn launch(&self, spec: &ToolSpec, target: String) -> Result<String> {
        let job_id = Uuid::new_v4().to_string();

        // Determine argv.
        let argv = spec.build_argv(&target, "proxychains4", false);
        if argv.is_empty() {
            bail!("empty argv for tool {}", spec.name);
        }

        // Check binary is present.
        if which::which(&argv[0]).is_err() {
            // Prompt user to install (send a notification; don't fail fatally).
            let _ = self.event_tx.send(AppEvent::Notification {
                level:   NotifLevel::Warning,
                message: format!("'{}' not found – run: sudo apt install {}", argv[0], spec.binary),
            });
        }

        let job = ScanJob {
            id:         job_id.clone(),
            tool:       spec.name.clone(),
            args:       argv.join(" "),
            target:     Some(target.clone()),
            status:     "running".into(),
            exit_code:  None,
            started_at: Utc::now(),
            ended_at:   None,
            output:     None,
        };
        if let Err(e) = self.db.insert_job(&job) {
            warn!(err = %e, "could not persist job");
        }

        // Build child process.
        let mut cmd = Command::new(&argv[0]);
        if argv.len() > 1 { cmd.args(&argv[1..]); }
        cmd.stdout(std::process::Stdio::piped())
           .stderr(std::process::Stdio::piped())
           .kill_on_drop(true);

        let mut child = match cmd.spawn() {
            Ok(c)  => c,
            Err(e) => {
                error!(err = %e, tool = %spec.name, "spawn failed");
                bail!("spawn failed: {e}");
            }
        };

        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let jid   = job_id.clone();
        let db    = Arc::clone(&self.db);
        let etx   = self.event_tx.clone();
        let spec2 = spec.clone();
        let tgt2  = target.clone();

        let handle = tokio::spawn(async move {
            let mut all_output = Vec::<String>::new();

            // Read stdout.
            let mut out_reader = BufReader::new(stdout).lines();
            // Read stderr.
            let mut err_reader = BufReader::new(stderr).lines();

            loop {
                tokio::select! {
                    line = out_reader.next_line() => {
                        match line {
                            Ok(Some(l)) => {
                                let _ = etx.send(AppEvent::ToolOutput { id: jid.clone(), line: l.clone() });
                                all_output.push(l.clone());
                                // Live parse for findings.
                                for f in parser::parse_line(&spec2, &l, &tgt2) {
                                    let _ = db.insert_finding(&f);
                                    let _ = etx.send(AppEvent::NewFinding(f));
                                }
                            }
                            Ok(None) => break,
                            Err(e) => { error!(err=%e, "stdout read error"); break; }
                        }
                    }
                    line = err_reader.next_line() => {
                        match line {
                            Ok(Some(l)) => {
                                let _ = etx.send(AppEvent::ToolOutput { id: jid.clone(), line: format!("[stderr] {l}") });
                                all_output.push(format!("[stderr] {l}"));
                            }
                            Ok(None) => {}
                            Err(_) => {}
                        }
                    }
                }
            }

            // Wait for exit.
            let output_str = all_output.join("\n");
            let exit_code = child
                .wait()
                .await
                .map(|s| s.code().unwrap_or(-1))
                .unwrap_or(-1);

            if let Err(e) = db.finish_job(&jid, exit_code, &output_str) {
                warn!(err = %e, "could not update job status");
            }

            let _ = etx.send(AppEvent::ToolFinished { id: jid.clone(), exit_code });
            info!(job = %jid, exit_code, "tool finished");
        });

        self.jobs.insert(job_id.clone(), handle.abort_handle());
        Ok(job_id)
    }

    /// Kill a running job.
    pub async fn kill(&self, job_id: &str) -> Result<()> {
        if let Some((_, abort)) = self.jobs.remove(job_id) {
            abort.abort();
            let _ = self.db.finish_job(job_id, -1, "killed by user");
            info!(job = %job_id, "job killed");
        }
        Ok(())
    }
}
