use std::collections::BTreeMap;

use silo::Session;

pub fn run(name: Option<&str>, ip: Option<std::net::Ipv4Addr>, json: bool) -> eyre::Result<()> {
    crate::sudoers::ensure()?;

    let ctx = silo::Context::current(name, ip)?;
    let backend = super::run::make_backend(&ctx)?;

    let session = Session::activate(ctx, silo::ActivateOptions::default(), backend)?;

    let mut vars: BTreeMap<String, String> = session
        .context()
        .env_vars()
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect();

    if session.backend_name() == "preload" {
        let lib_path = super::run::find_bind_lib()?;

        #[cfg(target_os = "macos")]
        let key = "DYLD_INSERT_LIBRARIES";
        #[cfg(target_os = "linux")]
        let key = "LD_PRELOAD";

        vars.insert(key.into(), lib_path.display().to_string());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&vars)?);
    } else {
        for (key, value) in &vars {
            println!("export {}={}", key, shell_escape(value));
        }
    }

    Ok(())
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_simple_string() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn escape_with_single_quote() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn escape_empty_string() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn escape_with_spaces() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
    }

    #[test]
    fn escape_with_special_chars() {
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
    }

    #[test]
    fn escape_path() {
        assert_eq!(
            shell_escape("/usr/local/lib/libsilo_bind.dylib"),
            "'/usr/local/lib/libsilo_bind.dylib'"
        );
    }

    #[test]
    fn escape_multiple_single_quotes() {
        assert_eq!(shell_escape("a'b'c"), "'a'\\''b'\\''c'");
    }
}
