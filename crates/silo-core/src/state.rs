use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

#[derive(Debug, Clone, Serialize, Deserialize, TypedBuilder)]
pub struct Instance {
    pub name: String,
    pub ip: Ipv4Addr,
    pub path: PathBuf,
    pub repo: PathBuf,
    pub is_worktree: bool,
    #[builder(default = Utc::now())]
    pub created_at: DateTime<Utc>,
}

impl Instance {
    pub fn env_vars(&self) -> HashMap<String, String> {
        let host = self.hostname();
        HashMap::from([
            ("SILO_NAME".into(), self.name.clone()),
            ("SILO_IP".into(), self.ip.to_string()),
            ("SILO_HOST".into(), host),
            ("SILO_REPO".into(), self.repo.display().to_string()),
            ("SILO_DIR".into(), self.path.display().to_string()),
            (
                "SILO_WORKTREE".into(),
                if self.is_worktree { "1" } else { "0" }.into(),
            ),
        ])
    }

    pub fn hostname(&self) -> String {
        let repo_dir = self
            .repo
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!("{}.{}.silo", self.name, repo_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn env_vars_correct() {
        let inst = Instance::builder()
            .name("api".to_string())
            .ip(Ipv4Addr::new(127, 0, 1, 1))
            .path(PathBuf::from("/work/api"))
            .repo(PathBuf::from("/repo"))
            .is_worktree(true)
            .build();
        let vars = inst.env_vars();
        assert_eq!(vars["SILO_NAME"], "api");
        assert_eq!(vars["SILO_IP"], "127.0.1.1");
        assert_eq!(vars["SILO_REPO"], "/repo");
        assert_eq!(vars["SILO_DIR"], "/work/api");
        assert_eq!(vars["SILO_WORKTREE"], "1");
    }

    #[test]
    fn hostname_format() {
        let inst = Instance::builder()
            .name("feature-a".to_string())
            .ip(Ipv4Addr::new(127, 0, 1, 1))
            .path(PathBuf::from("/work/api"))
            .repo(PathBuf::from("/home/user/myproject"))
            .is_worktree(true)
            .build();
        assert_eq!(inst.hostname(), "feature-a.myproject.silo");
    }
}
