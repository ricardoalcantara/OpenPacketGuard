use std::io;

use crate::{database::SharedDatabase, error::OPGError};
use ratatui::{
    crossterm::event::{self, KeyCode, KeyEventKind},
    style::Stylize,
    widgets::Paragraph,
    DefaultTerminal,
};

pub fn run(_db: SharedDatabase) -> Result<(), OPGError> {
    let mut terminal = ratatui::init();
    terminal.clear()?;
    let app_result = run_loop(terminal);
    ratatui::restore();
    app_result
}

fn run_loop(mut terminal: DefaultTerminal) -> Result<(), OPGError> {
    loop {
        terminal.draw(|frame| {
            let greeting = Paragraph::new("Hello Ratatui! (press 'q' to quit)").white();
            frame.render_widget(greeting, frame.area());
        })?;

        if let event::Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                return Ok(());
            }
        }
    }
}
