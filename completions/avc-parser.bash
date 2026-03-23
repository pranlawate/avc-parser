# Bash completion for avc-parser
# Install to /usr/share/bash-completion/completions/avc-parser

_avc_parser() {
    local cur prev words cword
    _init_completion || return

    local input_opts="-f --file -rf --raw-file -af --avc-file"
    local display_opts="--json --fields --detailed --report --pager"
    local filter_opts="--process --path --source --target --since --until"
    local sort_opts="--sort"
    local advanced_opts="--legacy-signatures -v --verbose --stats"
    local all_opts="$input_opts $display_opts $filter_opts $sort_opts $advanced_opts --help"

    # Complete file path after input options
    case "$prev" in
        -f|--file|-rf|--raw-file|-af|--avc-file)
            _filedir
            return
            ;;
        --report)
            COMPREPLY=($(compgen -W "brief sealert" -- "$cur"))
            return
            ;;
        --sort)
            COMPREPLY=($(compgen -W "recent count chrono" -- "$cur"))
            return
            ;;
        --process|--path|--source|--target|--since|--until)
            return
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$all_opts" -- "$cur"))
    fi
}

complete -F _avc_parser avc-parser
