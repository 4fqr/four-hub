// ─── Four-Hub · tui/events.rs ────────────────────────────────────────────────
//! Internal event bus types and the crossterm event bridge.

use crate::db::Finding;
use crossterm::event::Event;
// (serde Deserialize/Serialize not used in this module)

// ── AppEvent ──────────────────────────────────────────────────────────────────
#[derive(Debug)]
pub enum AppEvent {
    /// Raw terminal event from crossterm.
    Terminal(Event),
    /// 500ms heartbeat for stat refreshes.
    Tick,
    /// A line of stdout/stderr from a running tool.
    ToolOutput { id: String, line: String },
    /// A tool process has exited.
    ToolFinished { id: String, exit_code: i32 },
    /// A new finding was parsed from tool output.
    NewFinding(Finding),
    /// UI notification to push to the notification bar.
    Notification { level: crate::tui::app_state::NotifLevel, message: String },
}

// ── EventStream ───────────────────────────────────────────────────────────────
/// Thin wrapper around crossterm's async event stream.
pub struct EventStream {
    inner: crossterm::event::EventStream,
}

impl EventStream {
    pub fn new() -> Self {
        use crossterm::event::EventStream;
        Self { inner: EventStream::new() }
    }

    pub async fn next_event(&mut self) -> anyhow::Result<Event> {
        use futures_util::StreamExt;
        self.inner
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("event stream closed"))?
            .map_err(Into::into)
    }
}
