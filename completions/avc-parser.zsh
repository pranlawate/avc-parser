#compdef avc-parser

_avc_parser() {
    _arguments \
        '(-f --file)'{-f,--file}'[Path to audit file]:file:_files' \
        '(-rf --raw-file)'{-rf,--raw-file}'[Path to raw audit.log]:file:_files' \
        '(-af --avc-file)'{-af,--avc-file}'[Path to pre-processed file]:file:_files' \
        '--json[Output in JSON format]' \
        '--fields[Field-by-field breakdown]' \
        '--detailed[Detailed view with per-PID timestamps]' \
        '--report[Report format]:format:(brief sealert)' \
        '--pager[Use interactive pager]' \
        '--process[Filter by process name]:process:' \
        '--path[Filter by file path]:path:' \
        '--source[Filter by source context]:context:' \
        '--target[Filter by target context]:context:' \
        '--since[Denials since time]:time:' \
        '--until[Denials until time]:time:' \
        '--sort[Sort order]:order:(recent count chrono)' \
        '--legacy-signatures[Use legacy deduplication]' \
        '(-v --verbose)'{-v,--verbose}'[Verbose output]' \
        '--stats[Show statistics]'
}

_avc_parser
