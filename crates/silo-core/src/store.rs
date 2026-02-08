use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use eyre::{Context, ContextCompat};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};
use tracing::debug;

use crate::error::SiloError;
use crate::state::Instance;

pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn open_default() -> eyre::Result<Self> {
        let home = dirs::home_dir().context("failed to determine home directory")?;
        Self::open(&home.join(".silo")).await
    }

    pub async fn open(state_dir: &Path) -> eyre::Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("failed to create {}", state_dir.display()))?;

        let db_path = state_dir.join("state.db");
        debug!(path = %db_path.display(), "opening state database");

        let opts = SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .context("failed to open state database")?;

        let store = Self { pool };
        store.run_migrations().await?;

        Ok(store)
    }

    async fn run_migrations(&self) -> eyre::Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS instances (
                repo        TEXT NOT NULL,
                name        TEXT NOT NULL,
                ip          TEXT NOT NULL,
                path        TEXT NOT NULL,
                is_worktree INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                PRIMARY KEY (repo, name)
            )",
        )
        .execute(&self.pool)
        .await
        .context("failed to create instances table")?;

        Ok(())
    }

    pub async fn list_all(&self) -> eyre::Result<Vec<Instance>> {
        let rows = sqlx::query("SELECT * FROM instances ORDER BY repo, name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(row_to_instance).collect()
    }

    pub async fn list_by_repo(&self, repo: &Path) -> eyre::Result<Vec<Instance>> {
        let repo_str = repo.display().to_string();
        let rows = sqlx::query("SELECT * FROM instances WHERE repo = ? ORDER BY name")
            .bind(&repo_str)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(row_to_instance).collect()
    }

    pub async fn get(&self, repo: &Path, name: &str) -> eyre::Result<Option<Instance>> {
        let repo_str = repo.display().to_string();
        let row = sqlx::query("SELECT * FROM instances WHERE repo = ? AND name = ?")
            .bind(&repo_str)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(row_to_instance).transpose()
    }

    pub async fn find_by_name(&self, name: &str) -> eyre::Result<Vec<Instance>> {
        let rows = sqlx::query("SELECT * FROM instances WHERE name = ?")
            .bind(name)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(row_to_instance).collect()
    }

    pub async fn find_by_path(&self, path: &Path) -> eyre::Result<Option<Instance>> {
        let rows = sqlx::query("SELECT * FROM instances")
            .fetch_all(&self.pool)
            .await?;

        let instances: Vec<Instance> = rows.iter().map(row_to_instance).collect::<eyre::Result<_>>()?;
        Ok(instances
            .into_iter()
            .filter(|inst| path.starts_with(&inst.path))
            .max_by_key(|inst| inst.path.components().count()))
    }

    pub async fn used_ips(&self) -> eyre::Result<HashSet<Ipv4Addr>> {
        let rows = sqlx::query("SELECT ip FROM instances")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .iter()
            .filter_map(|row| row.get::<String, _>("ip").parse().ok())
            .collect())
    }

    pub async fn count(&self) -> eyre::Result<usize> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM instances")
            .fetch_one(&self.pool)
            .await?;
        Ok(count as usize)
    }

    pub async fn insert(&self, instance: &Instance) -> eyre::Result<()> {
        sqlx::query(
            "INSERT INTO instances (repo, name, ip, path, is_worktree, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(instance.repo.display().to_string())
        .bind(&instance.name)
        .bind(instance.ip.to_string())
        .bind(instance.path.display().to_string())
        .bind(instance.is_worktree)
        .bind(instance.created_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .context("failed to insert instance")?;

        Ok(())
    }

    pub async fn remove(&self, repo: &Path, name: &str) -> eyre::Result<bool> {
        let result = sqlx::query("DELETE FROM instances WHERE repo = ? AND name = ?")
            .bind(repo.display().to_string())
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn resolve_instance(
        &self,
        name: Option<&str>,
        cwd: &Path,
    ) -> eyre::Result<Instance> {
        match name {
            Some(name) => {
                if let Some(current) = self.find_by_path(cwd).await? {
                    if let Some(inst) = self.get(&current.repo, name).await? {
                        return Ok(inst);
                    }
                    return Err(SiloError::InstanceNotFound(name.to_string()).into());
                }

                let matches = self.find_by_name(name).await?;
                match matches.len() {
                    0 => Err(SiloError::InstanceNotFound(name.to_string()).into()),
                    1 => Ok(matches.into_iter().next().unwrap()),
                    _ => Err(SiloError::AmbiguousInstance(name.to_string(), matches).into()),
                }
            }
            None => self
                .find_by_path(cwd)
                .await?
                .ok_or_else(|| SiloError::NotInInstance.into()),
        }
    }
}

fn row_to_instance(row: &SqliteRow) -> eyre::Result<Instance> {
    use chrono::{DateTime, Utc};

    Ok(Instance {
        name: row.get("name"),
        ip: row
            .get::<String, _>("ip")
            .parse()
            .context("corrupt IP address in database")?,
        path: PathBuf::from(row.get::<String, _>("path")),
        repo: PathBuf::from(row.get::<String, _>("repo")),
        is_worktree: row.get("is_worktree"),
        created_at: row
            .get::<String, _>("created_at")
            .parse::<DateTime<Utc>>()
            .context("corrupt timestamp in database")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_instance(name: &str, ip: [u8; 4], path: &str, repo: &str) -> Instance {
        Instance::builder()
            .name(name.to_string())
            .ip(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
            .path(PathBuf::from(path))
            .repo(PathBuf::from(repo))
            .is_worktree(true)
            .build()
    }

    #[tokio::test]
    async fn empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let all = store.list_all().await.unwrap();
        assert!(all.is_empty());
        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn insert_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let inst = make_instance("api", [127, 0, 1, 1], "/work/api", "/repo");
        store.insert(&inst).await.unwrap();

        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "api");
        assert_eq!(all[0].ip, Ipv4Addr::new(127, 0, 1, 1));
    }

    #[tokio::test]
    async fn get_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let inst = make_instance("api", [127, 0, 1, 1], "/work/api", "/repo");
        store.insert(&inst).await.unwrap();

        let found = store.get(Path::new("/repo"), "api").await.unwrap();
        assert!(found.is_some());

        let removed = store.remove(Path::new("/repo"), "api").await.unwrap();
        assert!(removed);

        let found = store.get(Path::new("/repo"), "api").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn list_by_repo_filters() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store.insert(&make_instance("api", [127, 0, 1, 1], "/work/a", "/repo-a")).await.unwrap();
        store.insert(&make_instance("web", [127, 0, 1, 2], "/work/b", "/repo-b")).await.unwrap();
        store.insert(&make_instance("svc", [127, 0, 1, 3], "/work/c", "/repo-a")).await.unwrap();

        let results = store.list_by_repo(Path::new("/repo-a")).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn find_by_path_deepest() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store.insert(&make_instance("outer", [127, 0, 1, 1], "/work", "/repo")).await.unwrap();
        store.insert(&make_instance("inner", [127, 0, 1, 2], "/work/nested", "/repo")).await.unwrap();

        let found = store.find_by_path(Path::new("/work/nested/src")).await.unwrap();
        assert_eq!(found.unwrap().name, "inner");
    }

    #[tokio::test]
    async fn used_ips() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store.insert(&make_instance("a", [127, 0, 1, 1], "/a", "/repo")).await.unwrap();
        store.insert(&make_instance("b", [127, 0, 1, 2], "/b", "/repo")).await.unwrap();

        let ips = store.used_ips().await.unwrap();
        assert!(ips.contains(&Ipv4Addr::new(127, 0, 1, 1)));
        assert!(ips.contains(&Ipv4Addr::new(127, 0, 1, 2)));
        assert_eq!(ips.len(), 2);
    }

    #[tokio::test]
    async fn resolve_by_name_inside_repo() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store.insert(&make_instance("api", [127, 0, 1, 1], "/work/api", "/repo")).await.unwrap();
        store.insert(&make_instance("web", [127, 0, 1, 2], "/work/web", "/repo")).await.unwrap();

        let found = store.resolve_instance(Some("web"), Path::new("/work/api/src")).await.unwrap();
        assert_eq!(found.name, "web");
    }

    #[tokio::test]
    async fn resolve_auto_from_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store.insert(&make_instance("api", [127, 0, 1, 1], "/work/api", "/repo")).await.unwrap();

        let found = store.resolve_instance(None, Path::new("/work/api/src")).await.unwrap();
        assert_eq!(found.name, "api");
    }

    #[tokio::test]
    async fn resolve_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let err = store.resolve_instance(Some("nope"), Path::new("/work")).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn resolve_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store.insert(&make_instance("api", [127, 0, 1, 1], "/work/a", "/repo-a")).await.unwrap();
        store.insert(&make_instance("api", [127, 0, 1, 2], "/work/b", "/repo-b")).await.unwrap();

        let err = store.resolve_instance(Some("api"), Path::new("/elsewhere")).await;
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("ambiguous"));
    }

    #[tokio::test]
    async fn persists_across_opens() {
        let dir = tempfile::tempdir().unwrap();

        {
            let store = Store::open(dir.path()).await.unwrap();
            store.insert(&make_instance("api", [127, 0, 1, 1], "/work/api", "/repo")).await.unwrap();
        }

        let store = Store::open(dir.path()).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 1);
    }

}
