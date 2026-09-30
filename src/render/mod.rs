//! Five views plus shared formatting/glyph helpers. TUI views (compact,
//! extended, table) require raw mode; classic and JSON stream without it.

pub mod format;
pub mod icons;
pub mod terminal;
pub mod view_classic;
pub mod view_compact;
pub mod view_extended;
pub mod view_json;
pub mod view_table;
