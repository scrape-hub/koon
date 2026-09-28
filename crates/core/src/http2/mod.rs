pub mod config;

pub use config::{
    ConnectionPing, HeaderCompression, HeadersPriority, Http2Config, PriorityFrame, PseudoHeader,
    SettingId, StreamDep, WindowUpdateRule,
};
