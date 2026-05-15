#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Action {
    None,
    Quit,
    SwitchPane,
    NavigateUp,
    NavigateDown,
    Enter,
    Back,
    Copy,
    Delete,
    ToggleTransferBar,
    ToggleAdmin,
    ToggleUsers,
    Refresh,
    ConfirmYes,
    ConfirmNo,
    NextTab,
    PrevTab,
}
