pub mod admin;
pub mod config;
pub mod cve;
pub mod error;
pub mod extract;
pub mod hostops;
pub mod jobs;
pub mod live;
pub mod notify;
pub mod ratelimit;
pub mod routes;
pub mod schedule;
pub mod security;
pub mod state;
pub mod status;
pub mod worker;

pub use routes::router;
pub use state::AppState;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
