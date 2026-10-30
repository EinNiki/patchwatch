use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgConnection, PgPool};

pub const MAX_ATTEMPTS: i32 = 8;

pub struct Job {
    pub id: i64,
    pub kind: String,
    pub payload: Value,
    pub attempts: i32,
}

/// Legt einen Job an; mit `dedupe_key` höchstens einmal je Schlüssel.
pub async fn enqueue(
    conn: &mut PgConnection,
    kind: &str,
    payload: Value,
    run_at: DateTime<Utc>,
    dedupe_key: Option<&str>,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "INSERT INTO jobs (kind, payload, run_at, dedupe_key) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (dedupe_key) DO NOTHING",
    )
    .bind(kind)
    .bind(payload)
    .bind(run_at)
    .bind(dedupe_key)
    .execute(&mut *conn)
    .await?;
    sqlx::query("SELECT pg_notify('pw_jobs', '')")
        .execute(&mut *conn)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Holt den nächsten fälligen Job; `SKIP LOCKED` erlaubt mehrere Worker, hängende Locks verfallen nach 5 min.
pub async fn claim(pool: &PgPool) -> sqlx::Result<Option<Job>> {
    let row: Option<(i64, String, Value, i32)> = sqlx::query_as(
        "UPDATE jobs SET locked_at = now(), attempts = attempts + 1 WHERE id = ( \
            SELECT id FROM jobs WHERE done_at IS NULL AND run_at <= now() \
              AND (locked_at IS NULL OR locked_at < now() - interval '5 minutes') \
            ORDER BY run_at FOR UPDATE SKIP LOCKED LIMIT 1) \
         RETURNING id, kind, payload, attempts",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id, kind, payload, attempts)| Job {
        id,
        kind,
        payload,
        attempts,
    }))
}

pub async fn complete(pool: &PgPool, id: i64) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE jobs SET done_at = now(), locked_at = NULL, last_error = NULL WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Backoff: 10 s · 2^Versuche, höchstens 1 h; nach `MAX_ATTEMPTS` wird der Job aufgegeben.
pub fn backoff_secs(attempts: i32) -> i64 {
    (10_i64 << attempts.clamp(0, 10)).min(3600)
}

pub async fn fail(pool: &PgPool, job: &Job, error: &str) -> sqlx::Result<()> {
    if job.attempts >= MAX_ATTEMPTS {
        sqlx::query(
            "UPDATE jobs SET done_at = now(), locked_at = NULL, last_error = $2 WHERE id = $1",
        )
        .bind(job.id)
        .bind(error)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE jobs SET locked_at = NULL, last_error = $2, run_at = now() + make_interval(secs => $3) WHERE id = $1",
        )
        .bind(job.id)
        .bind(error)
        .bind(backoff_secs(job.attempts) as f64)
        .execute(pool)
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_secs(1), 20);
        assert_eq!(backoff_secs(3), 80);
        assert_eq!(backoff_secs(9), 3600);
        assert_eq!(backoff_secs(50), 3600);
    }
}
