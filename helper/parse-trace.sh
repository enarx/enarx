#!/bin/bash

SHIM="$1"
PAYLOAD="$2"

if [[ -z $SHIM ]]; then
    echo "Usage: $0 <shim> [<payload>]"
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

    if [[ $line = "Error: Shutdown"* ]]; then
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
        if [[ $line = *"rflags:"* ]] || [[ $line = *"rsp:"* ]] || [[ $line = *"rbp:"* ]]; then
            continue
        fi
    fi

    if [[ $ADDR2LINE = "TRACE" ]] && [[ $line = "P "* ]]; then
        if [[ $PAYLOAD ]]; then
            addr2line -apiCf -e "$PAYLOAD" $line | grep -F -v '??' | \
            while read line; do
                 printf -- "Payl: %s\n" "$line"
            done
            continue
        else
            printf -- "Payl: %s\n" "$line"
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
