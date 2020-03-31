#!/bin/sh

function usage() {
    echo "Usage: $0 --kernel <kernel> --app <app> -- <extra-args>" >&2
    exit 1
}

if [[ $1 == "--help" ]]; then
    usage
fi

TEMP=$(unset POSIXLY_CORRECT; getopt \
    -o "h" \
    --long help \
    --long kernel: \
    --long app: \
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
        --kernel)   kernel="$2"; shift;;
        --app)      app="$2"; shift;;
        -h|--help)  usage;;
        --)         shift; break;;
    esac
    shift
done

if [[ -z $kernel ]] || [[ -z $app ]]; then
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
   -kernel "$kernel" \
   -initrd "$app" \
   "$@"

ret=$?

[ $ret -eq 33 ] && exit 0

exit $ret
