// src/registration/websocket/terminal.rs
// Terminal support for WebSocket connections

use crate::registration::RegistrationManager;
use crate::terminal::{TerminalMessage, TerminalSessionManager, terminal_output_reader};
use std::sync::Arc;
use tokio::sync::mpsc;

impl RegistrationManager {
    /// Start terminal output reader task with proper channel handling
    pub(super) async fn start_terminal_output_reader(
        &self,
        terminal_manager: Arc<TerminalSessionManager>,
        session_id: String,
        tx: mpsc::Sender<TerminalMessage>,
    ) {
        // Spawn output reader task
        tokio::spawn(async move {
            terminal_output_reader(terminal_manager, session_id, tx).await;
        });
    }
}

/// Handle terminal messages from WebSocket
pub async fn handle_terminal_message(
    terminal_manager: &Arc<TerminalSessionManager>,
    message: TerminalMessage,
) -> Result<Option<TerminalMessage>, String> {
    use crate::terminal::handle_terminal_message as internal_handler;
    
    // Forward to the actual terminal handler and convert error type
    internal_handler(terminal_manager, message).await.map_err(|e| e.to_string())
}
