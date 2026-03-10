// ─── Four-Hub · app.rs ───────────────────────────────────────────────────────
//! Top-level application orchestrator.  Owns the event-loop, drives the TUI
//! renderer, dispatches keyboard/mouse events, and coordinates all subsystems.

use crate::{
    config::AppConfig,
    crypto::vault::VaultKey,
    db::Database,
    plugins::runtime::PluginRuntime,
    tools::{executor::ToolExecutor, registry::ToolRegistry},
    tui::{
        app_state::{ActiveView, AppState, ConfirmAction, ContextAction, NotifLevel, PopupKind},
        events::{AppEvent, EventStream},
        renderer::Renderer,
    },
};
use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyModifiers, MouseEventKind};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing::{error, info};

/// Main application struct – owns all subsystems.
pub struct Application {
    state:     AppState,
    renderer:  Renderer,
    executor:  Arc<ToolExecutor>,
    plugin_rt: Arc<PluginRuntime>,
    event_tx:  mpsc::UnboundedSender<AppEvent>,
    event_rx:  mpsc::UnboundedReceiver<AppEvent>,
    db:        Arc<Database>,
}

impl Application {
    pub fn new(
        cfg:       AppConfig,
        db:        Database,
        _vault_key: VaultKey,
        registry:  ToolRegistry,
        plugin_rt: PluginRuntime,
    ) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let db = Arc::new(db);
        let plugin_rt = Arc::new(plugin_rt);
        // Extract registry data BEFORE the registry is consumed by the executor.
        let all_tools_map = registry.export_all();
        let categories: Vec<String> = {
            let mut cats: Vec<String> = all_tools_map.keys().cloned().collect();
            cats.sort();
            cats
        };
        let first_tools = categories.first()
            .and_then(|cat| all_tools_map.get(cat))
            .cloned()
            .unwrap_or_default();

        let executor = Arc::new(ToolExecutor::new(
            Arc::clone(&db),
            registry,
            event_tx.clone(),
            Arc::clone(&plugin_rt),
        ));
        let mut state = AppState::new(cfg.clone(), Arc::clone(&db));
        state.all_tools        = all_tools_map;
        state.tool_categories  = categories;
        state.tools_in_category = first_tools;
        let renderer = Renderer::new()?;

        Ok(Self {
            state,
            renderer,
            executor,
            plugin_rt,
            event_tx,
            event_rx,
            db,
        })
    }

    /// Main run loop – drives TUI + event dispatch until the user quits.
    pub async fn run(&mut self) -> Result<()> {
        self.renderer.enter()?;

        // Spawn crossterm event reader.
        let event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            let mut reader = EventStream::new();
            loop {
                match reader.next_event().await {
                    Ok(ev) => {
                        if event_tx.send(AppEvent::Terminal(ev)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!(err = %e, "terminal event read error");
                        break;
                    }
                }
            }
        });

        // Spawn 1 Hz ticker for live stats refresh.
        let tick_tx = self.event_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                if tick_tx.send(AppEvent::Tick).is_err() {
                    break;
                }
            }
        });

        // Main event dispatch loop.
        loop {
            // Draw frame.
            self.renderer.draw(&self.state)?;

            // Wait for next event (with timeout so we always redraw).
            let Some(event) = self.event_rx.recv().await else {
                break;
            };

            match event {
                AppEvent::Tick => {
                    self.state.update_stats(&self.db).await;
                    // Execute any pending shell command from the embedded terminal.
                    if let Some(cmd) = self.state.pending_terminal_cmd.take() {
                        self.run_shell_cmd(cmd).await;
                    }
                }

                AppEvent::ToolOutput { id, line } => {
                    self.state.append_tool_output(&id, line.clone());
                    // Mirror all tool output to the embedded terminal.
                    self.state.push_terminal_line(line);
                }

                AppEvent::ToolFinished { id, exit_code } => {
                    info!(tool_id = %id, exit_code, "tool finished");
                    self.state.mark_tool_finished(&id, exit_code);
                    let _ = self.plugin_rt.fire_tool_finished(&id, exit_code).await;
                    let badge = if exit_code == 0 { "✓" } else { "✗" };
                    self.state.push_terminal_line(
                        format!("{badge} Job {} finished (exit {})", &id[..8.min(id.len())], exit_code)
                    );
                }

                AppEvent::NewFinding(finding) => {
                    self.state.push_finding(finding.clone());
                    let _ = self.plugin_rt.fire_new_finding(&finding).await;
                }

                AppEvent::Notification { level, message } => {
                    self.state.push_notification(level, message);
                }

                AppEvent::Terminal(ev) => {
                    if self.handle_terminal_event(ev).await? {
                        break; // quit
                    }
                }
            }
        }

        self.renderer.leave()?;
        Ok(())
    }

    // ── shell execution ───────────────────────────────────────────────────────

    async fn run_shell_cmd(&mut self, cmd: String) {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;

        let etx = self.event_tx.clone();
        let child = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn();

        match child {
            Err(e) => { self.state.push_terminal_line(format!("ERROR: {e}")); }
            Ok(mut child) => {
                let stdout = child.stdout.take().expect("stdout");
                let stderr = child.stderr.take().expect("stderr");
                tokio::spawn(async move {
                    let mut out = BufReader::new(stdout).lines();
                    let mut err = BufReader::new(stderr).lines();
                    loop {
                        tokio::select! {
                            line = out.next_line() => match line {
                                Ok(Some(l)) => { let _ = etx.send(AppEvent::ToolOutput { id: "shell".into(), line: l }); }
                                _ => break,
                            },
                            line = err.next_line() => match line {
                                Ok(Some(l)) => { let _ = etx.send(AppEvent::ToolOutput { id: "shell".into(), line: format!("[err] {l}") }); }
                                _ => {}
                            },
                        }
                    }
                    let _ = child.wait().await;
                    let _ = etx.send(AppEvent::Notification { level: NotifLevel::Info, message: "shell cmd done".into() });
                });
            }
        }
    }

    // ── event routing ─────────────────────────────────────────────────────────

    async fn handle_terminal_event(&mut self, ev: Event) -> Result<bool> {
        match ev {
            Event::Key(key)    => self.handle_key(key).await,
            Event::Mouse(m)    => { self.handle_mouse(m); Ok(false) }
            Event::Resize(w,h) => { self.state.resize(w, h); Ok(false) }
            _                  => Ok(false),
        }
    }

    // ── key handling — popup takes full priority ───────────────────────────────

    async fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Result<bool> {
        // 1. Any open popup captures ALL keys.
        if self.state.popup.is_some() {
            return self.handle_popup_key(key).await;
        }

        // 2. Embedded terminal is focused → forward input.
        if self.state.terminal_focused() {
            match key.code {
                KeyCode::Esc => self.state.blur_terminal(),
                _ => {
                    if let Some(cmd) = self.state.terminal_input(key) {
                        self.state.pending_terminal_cmd = Some(cmd);
                    }
                }
            }
            return Ok(false);
        }

        // 3. Global bindings.
        match (key.modifiers, key.code) {
            // Quit
            (KeyModifiers::CONTROL, KeyCode::Char('c'))
            | (KeyModifiers::NONE,  KeyCode::Char('q')) => return Ok(true),

            // View switching — F-keys AND digit keys
            (KeyModifiers::NONE, KeyCode::F(1)) | (KeyModifiers::NONE, KeyCode::Char('1')) => {
                self.state.set_view(ActiveView::Dashboard);
            }
            (KeyModifiers::NONE, KeyCode::F(2)) | (KeyModifiers::NONE, KeyCode::Char('2')) => {
                self.state.set_view(ActiveView::ToolLauncher);
            }
            (KeyModifiers::NONE, KeyCode::F(3)) | (KeyModifiers::NONE, KeyCode::Char('3')) => {
                self.state.set_view(ActiveView::Workspace);
            }
            (KeyModifiers::NONE, KeyCode::F(4)) | (KeyModifiers::NONE, KeyCode::Char('4')) => {
                self.state.set_view(ActiveView::Inspector);
            }
            (KeyModifiers::NONE, KeyCode::F(5)) | (KeyModifiers::NONE, KeyCode::Char('5')) => {
                self.state.set_view(ActiveView::Terminal);
                self.state.terminal.focused = true;
            }

            // Navigation
            (KeyModifiers::NONE, KeyCode::Up)   | (KeyModifiers::NONE, KeyCode::Char('k')) => {
                self.state.select_prev();
            }
            (KeyModifiers::NONE, KeyCode::Down) | (KeyModifiers::NONE, KeyCode::Char('j')) => {
                self.state.select_next();
            }
            // Left/Right — category nav in Launcher, panel nav elsewhere
            (KeyModifiers::NONE, KeyCode::Left) => {
                if self.state.active_view() == ActiveView::ToolLauncher {
                    self.state.prev_category();
                }
            }
            (KeyModifiers::NONE, KeyCode::Right) => {
                if self.state.active_view() == ActiveView::ToolLauncher {
                    self.state.next_category();
                }
            }
            (KeyModifiers::NONE, KeyCode::Tab) => self.state.next_panel(),
            (KeyModifiers::SHIFT, KeyCode::BackTab) => {
                if self.state.active_view() == ActiveView::ToolLauncher {
                    self.state.prev_category();
                }
            }

            (KeyModifiers::NONE, KeyCode::Enter) => self.handle_enter().await?,
            (KeyModifiers::NONE, KeyCode::Esc)   => self.state.dismiss_popup(),

            // Tool operations
            (KeyModifiers::NONE, KeyCode::Char('r')) => self.launch_selected_tool().await?,
            (KeyModifiers::NONE, KeyCode::Char('x')) => {
                if let Some(idx) = self.state.selected_job {
                    if let Some(job) = self.state.jobs.get(idx) {
                        let id    = job.id.clone();
                        let short = id[..8.min(id.len())].to_string();
                        self.state.popup = Some(PopupKind::Confirm {
                            msg:    format!("Kill job {short}?"),
                            action: ConfirmAction::KillJob(id),
                        });
                    }
                } else {
                    self.notify(NotifLevel::Warning, "No job selected".into());
                }
            }

            // Set target
            (KeyModifiers::NONE, KeyCode::Char('t')) => {
                self.state.popup = Some(PopupKind::TargetInput {
                    query: self.state.current_target.clone(),
                });
            }

            // Help
            (KeyModifiers::NONE, KeyCode::Char('?'))
            | (KeyModifiers::NONE, KeyCode::F(10)) => {
                self.state.popup = Some(PopupKind::Help);
            }

            // Clear terminal
            (KeyModifiers::CONTROL, KeyCode::Char('l')) => {
                self.state.terminal.lines.clear();
            }

            // Export report
            (KeyModifiers::CONTROL, KeyCode::Char('e')) => self.export_report().await?,

            // Search
            (KeyModifiers::CONTROL, KeyCode::Char('f')) => self.state.open_search(),

            // Inspector
            (KeyModifiers::NONE, KeyCode::Char('i')) => {
                self.state.open_inspector_for_selected();
            }

            // Delete finding
            (KeyModifiers::NONE, KeyCode::Char('d')) => {
                if let Some(idx) = self.state.selected_finding {
                    if let Some(f) = self.state.findings.get(idx) {
                        let fid   = f.id.clone();
                        let title = f.title.chars().take(30).collect::<String>();
                        self.state.popup = Some(PopupKind::Confirm {
                            msg:    format!("Delete finding: {title}?"),
                            action: ConfirmAction::DeleteFinding(fid),
                        });
                    }
                }
            }

            (KeyModifiers::NONE, KeyCode::PageUp)   => self.state.page_up(),
            (KeyModifiers::NONE, KeyCode::PageDown) => self.state.page_down(),
            (KeyModifiers::NONE, KeyCode::Home)     => self.state.scroll_top(),
            (KeyModifiers::NONE, KeyCode::End)      => self.state.scroll_bottom(),

            _ => {}
        }
        Ok(false)
    }

    // ── popup key handler ─────────────────────────────────────────────────────

    async fn handle_popup_key(&mut self, key: crossterm::event::KeyEvent) -> Result<bool> {
        if key.code == KeyCode::Esc {
            self.state.popup = None;
            return Ok(false);
        }

        let popup = match self.state.popup.clone() {
            Some(p) => p,
            None    => return Ok(false),
        };

        match popup {
            PopupKind::TargetInput { ref query } => {
                match key.code {
                    KeyCode::Enter => {
                        let target = query.clone();
                        self.state.current_target = target.clone();
                        self.state.popup = None;
                        if target.is_empty() {
                            self.notify(NotifLevel::Warning, "Target cleared".into());
                        } else {
                            self.notify(NotifLevel::Success, format!("Target → {target}"));
                        }
                    }
                    KeyCode::Backspace => {
                        if let Some(PopupKind::TargetInput { ref mut query }) = self.state.popup {
                            query.pop();
                        }
                    }
                    KeyCode::Delete => {
                        if let Some(PopupKind::TargetInput { ref mut query }) = self.state.popup {
                            query.clear();
                        }
                    }
                    KeyCode::Char(c) => {
                        if let Some(PopupKind::TargetInput { ref mut query }) = self.state.popup {
                            query.push(c);
                        }
                    }
                    _ => {}
                }
            }

            PopupKind::Confirm { action, .. } => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Enter => {
                        self.state.popup = None;
                        self.handle_confirm_action(action).await?;
                    }
                    _ => { self.state.popup = None; }
                }
            }

            PopupKind::ContextMenu { items, .. } => {
                match key.code {
                    KeyCode::Enter => {
                        if let Some(item) = items.into_iter().next() {
                            let action = item.action;
                            self.state.popup = None;
                            self.handle_context_action(action).await?;
                        }
                    }
                    _ => { self.state.popup = None; }
                }
            }

            _ => { self.state.popup = None; }
        }
        Ok(false)
    }

    // ── mouse handling ────────────────────────────────────────────────────────

    fn handle_mouse(&mut self, ev: crossterm::event::MouseEvent) {
        match ev.kind {
            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                self.state.popup = None; // dismiss any open popup
                self.state.click(ev.column, ev.row);
            }
            MouseEventKind::Down(crossterm::event::MouseButton::Right) => {
                self.state.context_menu(ev.column, ev.row);
            }
            MouseEventKind::ScrollUp   => self.state.scroll_up(),
            MouseEventKind::ScrollDown => self.state.scroll_down(),
            MouseEventKind::Drag(crossterm::event::MouseButton::Left) => {
                self.state.drag(ev.column, ev.row);
            }
            _ => {}
        }
    }

    // ── action handlers ───────────────────────────────────────────────────────

    async fn handle_enter(&mut self) -> Result<()> {
        match self.state.active_view() {
            ActiveView::ToolLauncher => self.launch_selected_tool().await?,
            ActiveView::Workspace    => self.state.open_inspector_for_selected(),
            ActiveView::Terminal     => { self.state.terminal.focused = true; }
            _                        => {}
        }
        Ok(())
    }

    async fn handle_confirm_action(&mut self, action: ConfirmAction) -> Result<()> {
        match action {
            ConfirmAction::KillJob(id) => {
                let _ = self.executor.kill(&id).await;
                self.state.mark_tool_finished(&id, -1);
                self.notify(NotifLevel::Info, format!("Job {} killed", &id[..8.min(id.len())]));
            }
            ConfirmAction::ExportReport => self.export_report().await?,
            ConfirmAction::DeleteFinding(id) => {
                self.state.findings.retain(|f| f.id != id);
                self.notify(NotifLevel::Info, "Finding removed".into());
            }
        }
        Ok(())
    }

    async fn handle_context_action(&mut self, action: ContextAction) -> Result<()> {
        match action {
            ContextAction::LaunchTool(spec) => {
                let target = self.state.current_target.clone();
                match self.executor.launch(&spec, target).await {
                    Ok(job_id) => {
                        self.state.register_job(job_id, spec.name.clone());
                        self.notify(NotifLevel::Success, format!("▶ {} started", spec.name));
                    }
                    Err(e) => self.notify(NotifLevel::Error, format!("Launch failed: {e}")),
                }
            }
            ContextAction::OpenInspector => self.state.open_inspector_for_selected(),
            ContextAction::CopyText(s) => {
                let _ = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(format!("printf '%s' '{}' | xclip -selection clipboard 2>/dev/null || printf '%s' '{}' | xsel --clipboard 2>/dev/null", s, s))
                    .spawn();
                self.notify(NotifLevel::Info, format!("Copied: {}", s.chars().take(40).collect::<String>()));
            }
        }
        Ok(())
    }

    async fn launch_selected_tool(&mut self) -> Result<()> {
        let spec = match self.state.selected_tool_spec() {
            Some(s) => s.clone(),
            None => {
                self.notify(NotifLevel::Warning, "No tool selected – use ↑/↓".into());
                return Ok(());
            }
        };

        // If the tool needs a target and none is set, show the target input popup.
        if spec.default_args.iter().any(|a| a.contains("{target}"))
            && self.state.current_target.is_empty()
        {
            self.state.popup = Some(PopupKind::TargetInput { query: String::new() });
            self.notify(NotifLevel::Warning, format!("{}: set a target first [t]", spec.name));
            return Ok(());
        }

        let target = self.state.current_target.clone();
        info!(tool = %spec.name, target = %target, "launching");

        match self.executor.launch(&spec, target).await {
            Ok(job_id) => {
                self.state.register_job(job_id, spec.name.clone());
                self.notify(NotifLevel::Success, format!("▶ {} started (Dashboard [1])", spec.name));
                self.state.set_view(ActiveView::Dashboard);
            }
            Err(e) => {
                error!(err = %e, "tool launch failed");
                self.notify(NotifLevel::Error, format!("Launch failed: {e}"));
            }
        }
        Ok(())
    }

    async fn export_report(&mut self) -> Result<()> {
        use crate::reporting;
        let findings = self.db.all_findings()?;
        let project  = self.state.project_name();

        let out_dir = dirs::download_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(format!("four-hub-report-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S")));
        std::fs::create_dir_all(&out_dir)?;

        reporting::html::export(&findings, &project, &out_dir.join("report.html"))?;
        reporting::json::export(&findings, &project, &out_dir.join("report.json"))?;

        self.notify(NotifLevel::Success, format!("Report → {}", out_dir.display()));
        Ok(())
    }

    fn notify(&self, level: NotifLevel, msg: String) {
        let _ = self.event_tx.send(AppEvent::Notification { level, message: msg });
    }
}
