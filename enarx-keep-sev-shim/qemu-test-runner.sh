#!/bin/sh

function usage() {
    echo "Usage: $0 --shim <shim> --code <code> -- <extra-args>" >&2
    exit 1
}

if [[ $1 == "--help" ]]; then
    usage
fi

TEMP=$(unset POSIXLY_CORRECT; getopt \
    -o "h" \
    --long help \
    --long shim: \
    --long code: \
    -- "$@")

if (( $? != 0 )); then
    usage
    exit 1
fi

eval set -- "$TEMP"

while :; do
    if [ $1 != "--" ] && [ $1 != "--rebuild" ]; then
        PARMS_TO_STORE+=" $1";
    fi
    case "$1" in
        --shim)     shim="$2"; shift;;
        --code)     code="$2"; shift;;
        -h|--help)  usage;;
        --)         shift; break;;
    esac
    shift
done

if [[ -z $shim ]] || [[ -z $code ]]; then
    usage
fi

qemu-system-x86_64 \
   -smp 1 \
   -m 128 \
   -nodefaults \
   -vga none \
   -display none \
   -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
   -chardev stdio,mux=on,id=char0 \
   -chardev file,path=/dev/stderr,id=char1 \
   -mon chardev=char0,mode=readline \
   -serial chardev:char0 \
   -serial chardev:char1 \
   -cpu max \
   -kernel "$shim" \
   -initrd "$code" \
   "$@"

ret=$?

[ $ret -eq 33 ] && exit 0

exit $ret
