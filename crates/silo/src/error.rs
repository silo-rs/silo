use thiserror::Error;

#[derive(Debug, Error)]
pub enum SiloError {
    #[error("not inside a git repository")]
    NotGitRepo,
}
