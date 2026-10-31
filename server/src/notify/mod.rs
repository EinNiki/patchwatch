//! Benachrichtigungen: Nachrichtentexte, Ereigniszuordnung, Kanäle (ntfy, Matrix, Gotify, Discord,
//! Live im Browser), Verschlüsselung der Geheimnisse und SSRF-Schutz.

pub mod channels;
pub mod crypto;
pub mod events;
pub mod messages;
pub mod smtp;
pub mod ssrf;
pub mod store;

pub use messages::*;
