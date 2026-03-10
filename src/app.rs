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
        app_state::{AppState, ActiveView},
        events::{AppEvent, EventStream},
        renderer::Renderer,
    },
};
use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyModifiers, MouseEventKind};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

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
                }

                AppEvent::ToolOutput { id, line } => {
                    self.state.append_tool_output(&id, line);
                }

                AppEvent::ToolFinished { id, exit_code } => {
                    info!(tool_id = %id, exit_code, "tool finished");
                    self.state.mark_tool_finished(&id, exit_code);
                    let _ = self.plugin_rt.fire_tool_finished(&id, exit_code).await;
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

    // ── event handlers ────────────────────────────────────────────────────────

    async fn handle_terminal_event(&mut self, ev: Event) -> Result<bool> {
        match ev {
            Event::Key(key) => self.handle_key(key).await,
            Event::Mouse(mouse) => {
                self.handle_mouse(mouse);
                Ok(false)
            }
            Event::Resize(w, h) => {
                self.state.resize(w, h);
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    async fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
    ) -> Result<bool> {
        // If the embedded terminal widget is focused, forward all input to it.
        if self.state.terminal_focused() {
            if key.code == KeyCode::Esc {
                self.state.blur_terminal();
                return Ok(false);
            }
            self.state.terminal_input(key);
            return Ok(false);
        }

        match (key.modifiers, key.code) {
            // Quit
            (KeyModifiers::CONTROL, KeyCode::Char('c'))
            | (KeyModifiers::NONE, KeyCode::Char('q')) => return Ok(true),

            // View switching (F-keys and digit keys both work)
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
            }

            // Navigation
            (KeyModifiers::NONE, KeyCode::Up | KeyCode::Char('k')) => {
                self.state.select_prev();
            }
            (KeyModifiers::NONE, KeyCode::Down | KeyCode::Char('j')) => {
                self.state.select_next();
            }
            // Launcher category navigation
            (KeyModifiers::NONE, KeyCode::Left | KeyCode::Char('h')) => {
                if self.state.active_view() == ActiveView::ToolLauncher {
                    self.state.prev_category();
                }
            }
            (KeyModifiers::NONE, KeyCode::Right | KeyCode::Char('l')) => {
                if self.state.active_view() == ActiveView::ToolLauncher {
                    self.state.next_category();
                }
            }
            (KeyModifiers::NONE, KeyCode::Enter) => {
                self.handle_enter().await?;
            }
            (KeyModifiers::NONE, KeyCode::Esc) => {
                self.state.dismiss_popup();
            }

            // Run selected tool
            (KeyModifiers::NONE, KeyCode::Char('r')) => {
                self.launch_selected_tool().await?;
            }

            // Stop selected job
            (KeyModifiers::NONE, KeyCode::Char('x')) => {
                self.state.kill_selected_job(&self.executor).await;
            }

            // Set target for tool
            (KeyModifiers::NONE, KeyCode::Char('t')) => {
                self.state.popup = Some(crate::tui::app_state::PopupKind::TargetInput {
                    query: self.state.current_target.clone(),
                });
            }

            // Help popup
            (KeyModifiers::NONE, KeyCode::Char('?')) => {
                self.state.popup = Some(crate::tui::app_state::PopupKind::Help);
            }

            // Clear embedded terminal
            (KeyModifiers::CONTROL, KeyCode::Char('l')) => {
                self.state.terminal.lines.clear();
            }

            // Export report
            (KeyModifiers::CONTROL, KeyCode::Char('e')) => {
                self.export_report().await?;
            }

            // Search / filter
            (KeyModifiers::CONTROL, KeyCode::Char('f')) => {
                self.state.open_search();
            }

            // Tab between panels
            (KeyModifiers::NONE, KeyCode::Tab) => {
                self.state.next_panel();
            }

            // Page navigation
            (KeyModifiers::NONE, KeyCode::PageUp) => self.state.page_up(),
            (KeyModifiers::NONE, KeyCode::PageDown) => self.state.page_down(),

            _ => {}
        }
        Ok(false)
    }

    fn handle_mouse(&mut self, ev: crossterm::event::MouseEvent) {
        match ev.kind {
            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                self.state.click(ev.column, ev.row);
            }
            MouseEventKind::Down(crossterm::event::MouseButton::Right) => {
                self.state.context_menu(ev.column, ev.row);
            }
            MouseEventKind::ScrollUp => self.state.scroll_up(),
            MouseEventKind::ScrollDown => self.state.scroll_down(),
            MouseEventKind::Drag(crossterm::event::MouseButton::Left) => {
                self.state.drag(ev.column, ev.row);
            }
            _ => {}
        }
    }

    async fn handle_enter(&mut self) -> Result<()> {
        match self.state.active_view() {
            ActiveView::ToolLauncher => self.launch_selected_tool().await?,
            ActiveView::Workspace    => self.state.open_inspector_for_selected(),
            ActiveView::Inspector    => {}
            _                       => {}
        }
        Ok(())
    }

    async fn launch_selected_tool(&mut self) -> Result<()> {
        let spec = match self.state.selected_tool_spec() {
            Some(s) => s.clone(),
            None => {
                warn!("launch attempted but no tool selected");
                return Ok(());
            }
        };
        let target = self.state.current_target().clone();
        info!(tool = %spec.name, "launching tool");
        match self.executor.launch(&spec, target).await {
            Ok(job_id) => {
                self.state.register_job(job_id, spec.name.clone());
                self.notify(crate::tui::app_state::NotifLevel::Info,
                    format!("Started: {}", spec.name));
            }
            Err(e) => {
                error!(err = %e, "tool launch failed");
                self.notify(crate::tui::app_state::NotifLevel::Error,
                    format!("Launch failed: {e}"));
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

        self.notify(crate::tui::app_state::NotifLevel::Success,
            format!("Report saved to {}", out_dir.display()));
        Ok(())
    }

    fn notify(&self, level: crate::tui::app_state::NotifLevel, msg: String) {
        let _ = self.event_tx.send(AppEvent::Notification { level, message: msg });
    }
}
