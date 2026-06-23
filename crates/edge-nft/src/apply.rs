use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use tokio::process::Command;
use tokio::time::timeout;

pub type Result<T> = std::result::Result<T, NftError>;

#[derive(Debug, Error)]
pub enum NftError {
    #[error("nft command timed out after {0:?}")]
    Timeout(Duration),
    #[error("nft process failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nft {
    binary: PathBuf,
    timeout: Duration,
}

impl Default for Nft {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("nft"),
            timeout: Duration::from_secs(5),
        }
    }
}

impl Nft {
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            ..Self::default()
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn check_file(&self, path: impl AsRef<Path>) -> Result<NftCommand> {
        self.run(["-c", "-f"], path.as_ref()).await
    }

    pub async fn apply_file(&self, path: impl AsRef<Path>) -> Result<NftCommand> {
        self.run(["-f", ""], path.as_ref()).await
    }

    async fn run<const N: usize>(&self, args: [&str; N], path: &Path) -> Result<NftCommand> {
        let mut command = Command::new(&self.binary);
        for arg in args.into_iter().filter(|arg| !arg.is_empty()) {
            command.arg(arg);
        }
        command.arg(path);
        let output = timeout(self.timeout, command.output())
            .await
            .map_err(|_| NftError::Timeout(self.timeout))??;
        Ok(NftCommand {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftCommand {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl NftCommand {
    pub fn is_success(&self) -> bool {
        self.status == Some(0)
    }

    pub fn error_message(&self) -> String {
        let stderr = self.stderr.trim();
        if stderr.is_empty() {
            format!("exit status {:?}", self.status)
        } else {
            stderr.to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reports_command_failure() {
        let nft = Nft::new("/usr/bin/false");
        let output = nft.check_file("/tmp/does-not-matter.nft").await.unwrap();

        assert!(!output.is_success());
        assert_eq!(output.error_message(), "exit status Some(1)");
    }
}
