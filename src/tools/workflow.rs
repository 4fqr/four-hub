
use crate::tools::{executor::ToolExecutor, registry::ToolRegistry};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Duration;
use tracing::info;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Concurrency {
    Sequential,
    Parallel,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStage {
    pub name:        String,
    pub tools:       Vec<String>,
    pub concurrency: Concurrency,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub name:        String,
    pub description: String,
    pub stages:      Vec<WorkflowStage>,
}

impl Workflow {
    pub async fn run(
        &self,
        target:   &str,
        executor: &Arc<ToolExecutor>,
        registry: &ToolRegistry,
    ) -> Result<Vec<String>> {
        let mut all_job_ids = Vec::new();

        for stage in &self.stages {
            info!(workflow = %self.name, stage = %stage.name, "starting stage");

            match stage.concurrency {
                Concurrency::Parallel => {
                    let mut handles = Vec::new();
                    for tool_name in &stage.tools {
                        if let Some(spec) = registry.find(tool_name) {
                            let ex = Arc::clone(executor);
                            let tgt = target.to_string();
                            handles.push(tokio::spawn(async move {
                                ex.launch(&spec, tgt).await
                            }));
                        }
                    }
                    for h in handles {
                        if let Ok(Ok(jid)) = h.await {
                            all_job_ids.push(jid);
                        }
                    }
                }
                Concurrency::Sequential => {
                    for tool_name in &stage.tools {
                        if let Some(spec) = registry.find(tool_name) {
                            match executor.launch(&spec, target.to_string()).await {
                                Ok(jid) => { all_job_ids.push(jid); }
                                Err(e)  => { tracing::warn!(err=%e, tool=%tool_name, "workflow tool failed"); }
                            }
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    }
                }
            }
        }

        Ok(all_job_ids)
    }
}
        Workflow {
            name:        "4-Elite Offensive".into(),
            description: "Null-Suite proprietary pipeline (4nmap → 4gobuster → 4nikto)".into(),
            stages: vec![
                WorkflowStage {
                    name: "Mapping",
                    tools: vec!["4nmap".into()],
                    concurrency: Concurrency::Sequential,
                },
                WorkflowStage {
                    name: "Fuzzing",
                    tools: vec!["4gobuster".into(), "4nikto".into()],
                    concurrency: Concurrency::Parallel,
                },
            ],
        },
        Workflow {
            name:        "Full Recon".into(),
            description: "Nmap + theHarvester + DNSenum + EyeWitness".into(),
            stages: vec![
                WorkflowStage {
                    name:        "Port Discovery".into(),
                    tools:       vec!["nmap".into()],
                    concurrency: Concurrency::Sequential,
                },
                WorkflowStage {
                    name:        "OSINT".into(),
                    tools:       vec!["theharvester".into(), "dnsenum".into()],
                    concurrency: Concurrency::Parallel,
                },
                WorkflowStage {
                    name:        "Screenshot".into(),
                    tools:       vec!["eyewitness".into()],
                    concurrency: Concurrency::Sequential,
                },
            ],
        },
        Workflow {
            name:        "Web Audit".into(),
            description: "Nikto + Gobuster + FFUF + SQLmap + Nuclei".into(),
            stages: vec![
                WorkflowStage {
                    name:        "Discovery".into(),
                    tools:       vec!["nikto".into(), "gobuster".into(), "ffuf".into()],
                    concurrency: Concurrency::Parallel,
                },
                WorkflowStage {
                    name:        "Exploitation".into(),
                    tools:       vec!["sqlmap".into(), "nuclei".into()],
                    concurrency: Concurrency::Parallel,
                },
            ],
        },
        Workflow {
            name:        "Network Spray".into(),
            description: "Masscan + Nmap + CrackMapExec + Enum4linux".into(),
            stages: vec![
                WorkflowStage {
                    name:        "Scan".into(),
                    tools:       vec!["masscan".into(), "nmap".into()],
                    concurrency: Concurrency::Sequential,
                },
                WorkflowStage {
                    name:        "Enum".into(),
                    tools:       vec!["crackmapexec".into(), "enum4linux".into()],
                    concurrency: Concurrency::Parallel,
                },
            ],
        },
        Workflow {
            name:        "Credential Hunt".into(),
            description: "Hydra (SSH + HTTP) + John on captured hashes".into(),
            stages: vec![
                WorkflowStage {
                    name:        "Brute-force".into(),
                    tools:       vec!["hydra".into()],
                    concurrency: Concurrency::Sequential,
                },
                WorkflowStage {
                    name:        "Offline Crack".into(),
                    tools:       vec!["john".into()],
                    concurrency: Concurrency::Sequential,
                },
            ],
        },
    ]
}
