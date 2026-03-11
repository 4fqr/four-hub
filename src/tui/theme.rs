
use ratatui::style::{Color, Modifier, Style};
pub const BG_BASE:     Color = Color::Rgb(10, 10, 18);
pub const BG_PANEL:    Color = Color::Rgb(16, 16, 30);
pub const BG_SELECTED: Color = Color::Rgb(28, 28, 50);
pub const BG_FOCUSED:  Color = Color::Rgb(20, 40, 65);

pub const NEON_GREEN:  Color = Color::Rgb(0,  255, 153);
pub const NEON_CYAN:   Color = Color::Rgb(0,  230, 255);
pub const NEON_PINK:   Color = Color::Rgb(255, 64, 200);
pub const NEON_YELLOW: Color = Color::Rgb(255, 234, 0);
pub const NEON_RED:    Color = Color::Rgb(255, 50,  80);
pub const NEON_ORANGE: Color = Color::Rgb(255,145,  0);

pub const FG_PRIMARY:   Color = Color::Rgb(220, 230, 255);
pub const FG_SECONDARY: Color = Color::Rgb(140, 150, 175);
pub const FG_DIM:       Color = Color::Rgb( 80,  90, 110);

pub const BORDER_NORMAL:  Color = Color::Rgb( 50,  55,  80);
pub const BORDER_FOCUSED: Color = NEON_CYAN;
pub const BORDER_ACTIVE:  Color = NEON_GREEN;
pub fn severity_color(sev: &str) -> Color {
    match sev.to_lowercase().as_str() {
        "critical" => NEON_RED,
        "high"     => NEON_ORANGE,
        "medium"   => NEON_YELLOW,
        "low"      => NEON_CYAN,
        _          => FG_SECONDARY,
    }
}

pub fn style_normal()   -> Style { Style::default().fg(FG_PRIMARY).bg(BG_BASE) }
pub fn style_title()    -> Style { Style::default().fg(NEON_GREEN).bg(BG_PANEL).add_modifier(Modifier::BOLD) }
pub fn style_selected() -> Style { Style::default().fg(BG_BASE).bg(NEON_GREEN).add_modifier(Modifier::BOLD) }
pub fn style_dim()      -> Style { Style::default().fg(FG_DIM).bg(BG_BASE) }
pub fn style_accent()   -> Style { Style::default().fg(NEON_CYAN).bg(BG_BASE) }
pub fn style_warning()  -> Style { Style::default().fg(NEON_YELLOW).bg(BG_BASE).add_modifier(Modifier::BOLD) }
pub fn style_error()    -> Style { Style::default().fg(NEON_RED).bg(BG_BASE).add_modifier(Modifier::BOLD) }
pub fn style_success()  -> Style { Style::default().fg(NEON_GREEN).bg(BG_BASE).add_modifier(Modifier::BOLD) }
pub fn style_panel()    -> Style { Style::default().fg(FG_PRIMARY).bg(BG_PANEL) }
pub fn style_border_focused() -> Style { Style::default().fg(BORDER_FOCUSED) }
pub fn style_border_active()  -> Style { Style::default().fg(BORDER_ACTIVE) }
pub fn style_border_normal()  -> Style { Style::default().fg(BORDER_NORMAL) }
pub fn style_popup()     -> Style { Style::default().fg(FG_PRIMARY).bg(Color::Rgb(20, 22, 40)) }
pub fn style_keybind()   -> Style { Style::default().fg(NEON_PINK).add_modifier(Modifier::BOLD) }
pub fn style_neon_pink() -> Style { Style::default().fg(NEON_PINK).bg(BG_BASE) }
pub fn style_critical()  -> Style { Style::default().fg(NEON_RED).bg(BG_BASE).add_modifier(Modifier::BOLD) }
pub fn style_high()      -> Style { Style::default().fg(NEON_ORANGE).bg(BG_BASE).add_modifier(Modifier::BOLD) }
pub fn style_installed() -> Style { Style::default().fg(NEON_GREEN).bg(BG_BASE) }
pub fn style_missing()   -> Style { Style::default().fg(NEON_RED).bg(BG_BASE) }
pub const BORDER_SET: ratatui::symbols::border::Set = ratatui::symbols::border::ROUNDED;
