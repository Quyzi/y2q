use throbber_widgets_tui::ThrobberState;

/// Wrapper around `ThrobberState` that only exists while an async op is in flight.
#[derive(Debug, Default)]
pub struct LoadingIndicator {
    pub state: ThrobberState,
    pub active: bool,
}

impl LoadingIndicator {
    pub fn start(&mut self) {
        self.active = true;
        self.state = ThrobberState::default();
    }

    pub fn stop(&mut self) {
        self.active = false;
    }

    pub fn tick(&mut self) {
        if self.active {
            self.state.calc_next();
        }
    }
}
