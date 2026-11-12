#!/usr/bin/env bash
# Replay one test case on a zephyr-syscall-fuzz ELF and print its crash record.
#
#   replay.sh [-g PORT [-w]] [-u UART_FILE] ELF INPUT
#
#   -g PORT  start a GDB server on PORT; after a failure the machine is kept
#            alive (spinning in k_sys_fatal_error_handler) until Ctrl-C
#   -w       with -g, do not start the CPU until the debugger continues
#   -u FILE  save the guest UART output to FILE

set -e

usage() {
    sed -n '2,10s/^# \{0,1\}//p' "$0" >&2
    exit 1
}

gdb_port=""
uart=""
while getopts "g:wu:h" opt; do
    case $opt in
    g) gdb_port=$OPTARG ;;
    w) export AFL_RENODE_NO_START=1 ;;
    u) uart=$(readlink -f "$OPTARG") ;;
    *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 2 ] || usage

elf=$(readlink -f "$1")
input=$(readlink -f "$2")
root=$(readlink -f "$(dirname "$0")/../..")

resc=$(mktemp --suffix=.resc)
trap 'rm -f "$resc"' EXIT
echo "include @$root/renode_mode/example-syscall.resc" >"$resc"
[ -n "$uart" ] && echo "sysbus.uart0 CreateFileBackend @$uart true" >>"$resc"
if [ -n "$gdb_port" ]; then
    echo "machine StartGdbServer $gdb_port true" >>"$resc"
    export AFL_RENODE_HOLD=1
    echo "Attach with: arm-zephyr-eabi-gdb $elf -ex 'target remote :$gdb_port'" >&2
fi

cd "$root"
# Drop the coverage map dump, Renode's peripheral warnings and the SystemExit
# backtrace printed when standalone mode quits
./afl-renode-trace "$resc" "$elf" <"$input" 2>&1 | stdbuf -oL tr -d '\r' |
    grep --line-buffered -vE '^\[[0-9]+, [0-9]+, |\[WARNING\]' |
    sed -u '/^Exiting with status/q'
