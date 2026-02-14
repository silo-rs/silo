use std::collections::BTreeMap;

use silo::Session;

pub fn run(name: Option<&str>, ip: Option<std::net::Ipv4Addr>, json: bool) -> eyre::Result<()> {
    crate::sudoers::ensure()?;

    let ctx = silo::Context::current(name, ip)?;
    let backend = super::run::make_backend(&ctx)?;

    let session = Session::activate(ctx, silo::ActivateOptions::default(), backend)?;

    let mut vars: BTreeMap<String, String> = session.context().env_vars().into_iter().collect();

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

/// Single-quote a value for safe shell eval.
fn shell_escape(s: &str) -> String {
    // Replace ' with '\'' (end quote, escaped quote, start quote)
    format!("'{}'", s.replace('\'', "'\\''"))
}
