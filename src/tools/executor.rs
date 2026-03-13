
use crate::{
    db::{Database, ScanJob},
    plugins::runtime::PluginRuntime,
    tools::{parser, parser::ParsedRecord, spec::ToolSpec},
    tui::app_state::NotifLevel,
    tui::events::AppEvent,
};
use anyhow::{bail, Result};
use chrono::Utc;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    sync::mpsc,
};
use tracing::{error, info, warn};
use uuid::Uuid;

struct JobHandle {
    child:   Child,
    spec:    ToolSpec,
    target:  String,
    output:  Vec<String>,
}

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
    pub async fn launch(&self, spec: &ToolSpec, target: String, wordlist: String) -> Result<String> {
        let job_id = Uuid::new_v4().to_string();

        if spec.is_builtin {
            return self.launch_builtin(spec, target, wordlist, job_id).await;
        }

        let argv = spec.build_argv(&target, &wordlist, "proxychains4", false);
        if argv.is_empty() {
            bail!("empty argv for tool {}", spec.name);
        }
        if which::which(&argv[0]).is_err() {
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
            let mut addr_to_hid: HashMap<String, String> = HashMap::new();
            let mut out_reader = BufReader::new(stdout).lines();
            let mut err_reader = BufReader::new(stderr).lines();

            loop {
                tokio::select! {
                    line = out_reader.next_line() => {
                        match line {
                            Ok(Some(l)) => {
                                let _ = etx.send(AppEvent::ToolOutput { id: jid.clone(), line: l.clone() });
                                all_output.push(l.clone());
                                for rec in parser::parse_line(&spec2, &l, &tgt2) {
                                    match rec {
                                        ParsedRecord::Finding(f) => {
                                            let _ = db.insert_finding(&f);
                                            let _ = etx.send(AppEvent::NewFinding(f));
                                        }
                                        ParsedRecord::NewHost(h) => {
                                            addr_to_hid.insert(h.address.clone(), h.id.clone());
                                            let _ = db.upsert_host(&h);
                                            let _ = etx.send(AppEvent::UpsertHost(h));
                                        }
                                        ParsedRecord::NewPort { mut port, host_addr } => {
                                            if let Some(hid) = addr_to_hid.get(&host_addr) {
                                                port.host_id = hid.clone();
                                            }
                                            if !port.host_id.is_empty() {
                                                let _ = db.upsert_port(&port);
                                                let _ = etx.send(AppEvent::UpsertPort(port));
                                            }
                                        }
                                    }
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
            let output_str = all_output.join("\n");
            let exit_code = child
                .wait()
                .await
                .map(|s| s.code().unwrap_or(-1))
                .unwrap_or(-1);

            if let Err(e) = db.finish_job(&jid, exit_code, &output_str) {
                warn!(err = %e, "could not update job status");
            }
            if spec2.name == "nmap" {
                let xml_path = format!("/tmp/fh_nmap_{tgt2}.xml");
                for rec in parser::parse_nmap_xml(&xml_path, &tgt2) {
                    match rec {
                        ParsedRecord::Finding(f) => {
                            let _ = db.insert_finding(&f);
                            let _ = etx.send(AppEvent::NewFinding(f));
                        }
                        ParsedRecord::NewHost(h) => {
                            addr_to_hid.insert(h.address.clone(), h.id.clone());
                            let _ = db.upsert_host(&h);
                            let _ = etx.send(AppEvent::UpsertHost(h));
                        }
                        ParsedRecord::NewPort { mut port, host_addr } => {
                            if let Some(hid) = addr_to_hid.get(&host_addr) {
                                port.host_id = hid.clone();
                            }
                            if !port.host_id.is_empty() {
                                let _ = db.upsert_port(&port);
                                let _ = etx.send(AppEvent::UpsertPort(port));
                            }
                        }
                    }
                }
            }

            let _ = etx.send(AppEvent::ToolFinished { id: jid.clone(), exit_code });
            info!(job = %jid, exit_code, "tool finished");
        });

        self.jobs.insert(job_id.clone(), handle.abort_handle());
        Ok(job_id)
    }
    pub async fn kill(&self, job_id: &str) -> Result<()> {
        if let Some((_, abort)) = self.jobs.remove(job_id) {
            abort.abort();
            let _ = self.db.finish_job(job_id, -1, "killed by user");
            info!(job = %job_id, "job killed");
        }
        Ok(())
    }

    async fn launch_builtin(&self, spec: &ToolSpec, target: String, wordlist: String, job_id: String) -> Result<String> {
        let (output_tx, mut output_rx) = mpsc::unbounded_channel::<String>();
        let etx = self.event_tx.clone();
        let jid = job_id.clone();
        let db  = Arc::clone(&self.db);
        let spec_name = spec.name.clone();

        let job = ScanJob {
            id:         job_id.clone(),
            tool:       spec.name.clone(),
            args:       spec.default_args.join(" "),
            target:     Some(target.clone()),
            status:     "running".into(),
            exit_code:  None,
            started_at: Utc::now(),
            ended_at:   None,
            output:     None,
        };
        let _ = self.db.insert_job(&job);

        let spec_for_parsing = spec.clone();
        let target_for_parsing = target.clone();
        let handle = tokio::spawn(async move {
            let jid_inner = jid.clone();
            let etx_inner = etx.clone();
            let db_inner = Arc::clone(&db);
            
            let output_handle = tokio::spawn(async move {
                let mut lines = Vec::new();
                let mut addr_to_hid = HashMap::new();
                while let Some(line) = output_rx.recv().await {
                    if line.starts_with("[PROGRESS] ") {
                        if let Ok(p) = line.trim_start_matches("[PROGRESS] ").replace('%', "").trim().parse::<f64>() {
                            let _ = etx_inner.send(AppEvent::ToolProgress { id: jid_inner.clone(), progress: p / 100.0 });
                            continue;
                        }
                    }
                    let _ = etx_inner.send(AppEvent::ToolOutput { id: jid_inner.clone(), line: line.clone() });
                    

                    for rec in parser::parse_line(&spec_for_parsing, &line, &target_for_parsing) {
                        match rec {
                            ParsedRecord::Finding(f) => {
                                let _ = db_inner.insert_finding(&f);
                                let _ = etx_inner.send(AppEvent::NewFinding(f));
                            }
                            ParsedRecord::NewHost(h) => {
                                addr_to_hid.insert(h.address.clone(), h.id.clone());
                                let _ = db_inner.upsert_host(&h);
                                let _ = etx_inner.send(AppEvent::UpsertHost(h));
                            }
                            ParsedRecord::NewPort { mut port, host_addr } => {
                                if let Some(hid) = addr_to_hid.get(&host_addr) {
                                    port.host_id = hid.clone();
                                }
                                if !port.host_id.is_empty() {
                                    let _ = db_inner.upsert_port(&port);
                                    let _ = etx_inner.send(AppEvent::UpsertPort(port));
                                }
                            }
                        }
                    }
                    lines.push(line);
                }
                lines
            });

            let res = match spec_name.as_str() {
                "4nmap" => {
                    let ports = (1..1025).collect();
                    crate::tools::null::nmap::run_4nmap(target, ports, 64, 1500, output_tx).await
                }
                "4gobuster" => {
                    crate::tools::null::gobuster::run_4gobuster(target, wordlist, 50, output_tx).await
                }
                "4hydra" => {
                    crate::tools::null::hydra::run_4hydra(target, "admin".into(), wordlist, 20, 2000, output_tx).await
                }
                "4nikto" => {
                    crate::tools::null::nikto::run_4nikto(target, output_tx).await
                }
                "4subfinder" => {
                    crate::tools::null::subfinder::run_4subfinder(target, wordlist, output_tx).await
                }
                _ => {
                    let _ = output_tx.send(format!("Error: built-in tool '{}' is registered but not implemented.", spec_name));
                    Ok(())
                }
            };

            let all_output = output_handle.await.unwrap_or_default();
            let exit_code = if res.is_ok() { 0 } else { 
                if let Err(e) = res {
                    let _ = etx.send(AppEvent::ToolOutput { id: jid.clone(), line: format!("ERROR: {e}") });
                }
                1 
            };
            
            let _ = db.finish_job(&jid, exit_code, &all_output.join("\n"));
            let _ = etx.send(AppEvent::ToolFinished { id: jid.clone(), exit_code });
        });

        self.jobs.insert(job_id.clone(), handle.abort_handle());
        Ok(job_id)
    }

    pub fn registry_find(&self, name: &str) -> Option<crate::tools::spec::ToolSpec> {
        self.registry.find(name)
    }
}
