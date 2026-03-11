
use crate::db::{Finding, Host, Port};
use crossterm::event::Event;
#[derive(Debug)]
pub enum AppEvent {
    Terminal(Event),
    Tick,
    ToolOutput { id: String, line: String },
    ToolFinished { id: String, exit_code: i32 },
    NewFinding(Finding),
    UpsertHost(Host),
    UpsertPort(Port),
    Notification { level: crate::tui::app_state::NotifLevel, message: String },
}
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
