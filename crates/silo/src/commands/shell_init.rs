pub fn run() -> eyre::Result<()> {
    let shell = std::env::var("SHELL").unwrap_or_default();

    if shell.contains("fish") {
        print!("{}", FISH_INIT);
    } else if shell.contains("zsh") {
        print!("{}", ZSH_INIT);
    } else {
        print!("{}", BASH_INIT);
    }

    Ok(())
}

const BASH_INIT: &str = r#"
__silo_env_hook() {
    # Fast path: still inside the same instance directory
    if [ -n "$__silo_instance_path" ]; then
        case "$PWD" in "$__silo_instance_path"*) return;; esac
    fi
    eval "$(command silo env 2>/dev/null)"
    if [ -n "$SILO_NAME" ]; then
        __silo_instance_path="${SILO_REPO:+$(command silo dir "$SILO_NAME" 2>/dev/null)}"
    else
        __silo_instance_path=""
    fi
}
if [[ ! "$PROMPT_COMMAND" =~ __silo_env_hook ]]; then
    PROMPT_COMMAND="__silo_env_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi

silo() {
    if [ "$1" = "cd" ]; then
        if [ -z "$2" ]; then
            echo "Usage: silo cd <instance>" >&2
            return 1
        fi
        local dir
        dir="$(command silo dir "$2")" && cd "$dir"
    else
        command silo "$@"
    fi
}

# Run activate once per boot (skip if already done this boot)
if [ ! -f "/tmp/.silo_activated_$(id -u)" ] || \
   [ "$(cat /tmp/.silo_activated_$(id -u) 2>/dev/null)" != "$(sysctl -n kern.boottime 2>/dev/null || who -b 2>/dev/null | awk '{print $3,$4}')" ]; then
    command silo activate 2>/dev/null && \
        (sysctl -n kern.boottime 2>/dev/null || who -b 2>/dev/null | awk '{print $3,$4}') > "/tmp/.silo_activated_$(id -u)" 2>/dev/null
fi
"#;

const ZSH_INIT: &str = r#"
__silo_env_hook() {
    # Fast path: still inside the same instance directory
    if [[ -n "$__silo_instance_path" ]]; then
        [[ "$PWD" = "$__silo_instance_path"* ]] && return
    fi
    eval "$(command silo env 2>/dev/null)"
    if [[ -n "$SILO_NAME" ]]; then
        __silo_instance_path="${SILO_REPO:+$(command silo dir "$SILO_NAME" 2>/dev/null)}"
    else
        __silo_instance_path=""
    fi
}
if (( ! ${+precmd_functions[(r)__silo_env_hook]} )); then
    autoload -Uz add-zsh-hook
    add-zsh-hook chpwd __silo_env_hook
fi
__silo_env_hook

silo() {
    if [[ "$1" == "cd" ]]; then
        if [[ -z "$2" ]]; then
            echo "Usage: silo cd <instance>" >&2
            return 1
        fi
        local dir
        dir="$(command silo dir "$2")" && cd "$dir"
    else
        command silo "$@"
    fi
}

# Dynamic completions for instance names
_silo() {
    local -a subcmds
    subcmds=(add list remove env info doctor prune run exec completions)
    _arguments '1:command:compadd -a subcmds' '*::arg:->args'
    case "$words[1]" in
        remove|info|cd|dir)
            local -a instances
            instances=(${(f)"$(command silo list --json 2>/dev/null | command grep -o '"name":"[^"]*"' | command sed 's/"name":"//;s/"//')"})
            compadd -a instances
            ;;
        run)
            local -a cmds
            cmds=(${(f)"$(command silo run 2>/dev/null | command awk '/^    /{print $1}')"})
            compadd -a cmds
            ;;
    esac
}
compdef _silo silo

# Run activate once per boot (skip if already done this boot)
if [[ ! -f "/tmp/.silo_activated_$(id -u)" ]] || \
   [[ "$(< /tmp/.silo_activated_$(id -u) 2>/dev/null)" != "$(sysctl -n kern.boottime 2>/dev/null || who -b 2>/dev/null | awk '{print $3,$4}')" ]]; then
    command silo activate 2>/dev/null && \
        (sysctl -n kern.boottime 2>/dev/null || who -b 2>/dev/null | awk '{print $3,$4}') > "/tmp/.silo_activated_$(id -u)" 2>/dev/null
fi
"#;

const FISH_INIT: &str = r#"
function __silo_env_hook --on-variable PWD
    # Fast path: still inside the same instance directory
    if set -q __silo_instance_path; and test -n "$__silo_instance_path"
        string match -q "$__silo_instance_path*" "$PWD"; and return
    end
    command silo env 2>/dev/null | source
    if set -q SILO_NAME; and test -n "$SILO_NAME"
        set -g __silo_instance_path (command silo dir "$SILO_NAME" 2>/dev/null)
    else
        set -g __silo_instance_path ""
    end
end

function silo
    if test "$argv[1]" = "cd"
        if test (count $argv) -lt 2
            echo "Usage: silo cd <instance>" >&2
            return 1
        end
        set -l dir (command silo dir $argv[2])
        and cd $dir
    else
        command silo $argv
    end
end

# Dynamic completions for instance names
complete -c silo -n '__fish_use_subcommand' -a 'add list remove env info doctor prune run exec completions'
complete -c silo -n '__fish_seen_subcommand_from remove info cd dir' -a '(command silo list --json 2>/dev/null | string match -r \'"name":"[^"]*"\' | string replace -r \'"name":"([^"]*)"\' \'$1\')'
complete -c silo -n '__fish_seen_subcommand_from run' -a '(command silo run 2>/dev/null | string match -r \'^\s+\S+\' | string trim)'

# Run activate once per boot
set -l _silo_marker "/tmp/.silo_activated_"(id -u)
set -l _silo_boottime (sysctl -n kern.boottime 2>/dev/null; or who -b 2>/dev/null | awk '{print $3,$4}')
if not test -f "$_silo_marker"; or test (cat "$_silo_marker" 2>/dev/null) != "$_silo_boottime"
    command silo activate 2>/dev/null
    and echo "$_silo_boottime" > "$_silo_marker" 2>/dev/null
end
__silo_env_hook
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_defines_required_functions() {
        assert!(BASH_INIT.contains("__silo_env_hook()"));
        assert!(BASH_INIT.contains("silo()"));
        assert!(BASH_INIT.contains("PROMPT_COMMAND"));
        assert!(BASH_INIT.contains("silo activate"));
    }

    #[test]
    fn zsh_defines_required_functions() {
        assert!(ZSH_INIT.contains("__silo_env_hook()"));
        assert!(ZSH_INIT.contains("silo()"));
        assert!(ZSH_INIT.contains("add-zsh-hook"));
        assert!(ZSH_INIT.contains("silo activate"));
    }

    #[test]
    fn fish_defines_required_functions() {
        assert!(FISH_INIT.contains("function __silo_env_hook"));
        assert!(FISH_INIT.contains("function silo"));
        assert!(FISH_INIT.contains("--on-variable PWD"));
        assert!(FISH_INIT.contains("silo activate"));
    }

    #[test]
    fn all_shells_handle_cd_subcommand() {
        // Each shell wrapper should intercept "silo cd <name>"
        assert!(BASH_INIT.contains(r#""$1" = "cd""#));
        assert!(ZSH_INIT.contains(r#""$1" == "cd""#));
        assert!(FISH_INIT.contains(r#""$argv[1]" = "cd""#));
    }

    #[test]
    fn all_shells_have_fast_path_cache() {
        // Each shell should cache the instance path for fast cd detection
        assert!(BASH_INIT.contains("__silo_instance_path"));
        assert!(ZSH_INIT.contains("__silo_instance_path"));
        assert!(FISH_INIT.contains("__silo_instance_path"));
    }
}
