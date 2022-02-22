#!/usr/bin/env bash

SHIM="$1"
PAYLOAD="$2"

if [[ -z $SHIM ]]; then
    echo "Usage: $0 <shim> [<exec>]"
fi

strstr() { [[ $1 = *"$2"* ]]; }

unset ADDR2LINE

while read line; do
    if [[ $line = "panicked at"* ]]; then
        printf -- "%s\n" "$line"
        continue
    fi

    if [[ $line = "TRACE:"* ]]; then
        printf -- "%s\n" "$line"
        ADDR2LINE="TRACE"
        continue
    fi

    if [[ $line = "Error: Shutdown"* ]] || [[ $line = "Error: MmioRead"* ]]; then
        ADDR2LINE="REGS"
        continue
    fi

    if ! [[ $ADDR2LINE ]]; then
        printf -- "%s\n" "$line"
        continue
    fi

    if ! [[ $line ]]; then
        continue
    fi

    if [[ $line = ")" ]]; then
        unset ADDR2LINE
    fi

    if [[ $ADDR2LINE = "REGS" ]]; then
        if [[ $line = *"rflags:"* ]] || [[ $line = *"rsp:"* ]] || [[ $line = *"rbp:"* ]] || [[ $line = *"rbx:"* ]]; then
            continue
        fi
        line=${line%,}
        read _ line <<< "$line"
        line=${line/ffffff8}
    fi

    if [[ $ADDR2LINE = "TRACE" ]] && [[ $line = "E "* ]]; then
        if [[ $PAYLOAD ]]; then
            addr2line -apiCf -e "$PAYLOAD" $line | grep -F -v '??' | \
            while read line; do
                 printf -- "Exec: %s\n" "$line"
            done
            continue
        else
            printf -- "Exec: %s\n" "$line"
            continue
        fi
    fi

    if [[ $SHIM ]]; then
        addr2line -apiCf -e "$SHIM" $line | grep -F -v '??' | \
            while read line; do
                 printf -- "Shim: %s\n" "$line"
            done
        continue
    else
        printf -- "Shim: %s\n" "$line"
        continue
    fi

done
