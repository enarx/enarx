#!/bin/sh

qemu-system-x86_64 \
   -smp 1 \
   -m 128 \
   -nodefaults \
   -vga none \
   -display none \
   -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
   -chardev stdio,mux=on,id=char0 \
   -mon chardev=char0,mode=readline \
   -serial chardev:char0 \
   -serial chardev:char0 \
   -cpu max \
   -kernel $@
ret=$?

[ $ret -eq 33 ] && exit 0

exit $ret
