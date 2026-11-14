#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run fuzzing campaigns for one or more syscall groups, in parallel.
#
#   campaign.sh [-d SECS] [-j JOBS] [-o OUT] [-c COVERAGE] [-n] [-w] GROUP=ELF...
#   campaign.sh -R OUT GROUP/INSTANCE...   restart (resume) instances
#   campaign.sh -S OUT                     status of every instance
#   campaign.sh -K OUT                     stop every instance
#
#   GROUP=ELF  campaign name and zephyr.elf built for it, e.g.
#              objects=../build-g-objects/zephyr/zephyr.elf
#              Seeds come from seeds/<GROUP up to the first '-'>, so
#              futex-kmutex=... uses seeds/futex.
#   -d SECS    duration of the campaign (default 600)
#   -j JOBS    afl-fuzz instances per group: main (-M) plus s1..sN (-S)
#              (default 1)
#   -o OUT     output directory (default
#              ${ZFUZZ_CAMPAIGNS:-$HOME/zfuzz}/<date>)
#   -c MODE    AFL_RENODE_COVERAGE: window (default), kernel or all
#   -n         print the commands instead of running them
#   -w         wait for the campaign to end and print the status
#
# Instances run in their own sessions, so they survive this script and
# the terminal; their pids are in OUT/<GROUP>/<INSTANCE>.pid. The ELF and
# its .cov are copied to OUT/<GROUP>/ and fuzzed from there, so rebuilding
# during a campaign does not affect it, and crashes can later be replayed
# against the exact binary (see replay.sh). Every instance writes
# OUT/<GROUP>/<INSTANCE>.log and crash records to OUT/<GROUP>/crash-info/.
# -R resumes an instance from its AFL output directory (afl-fuzz -i -)
# for the rest of the campaign time; see watchdog.sh for monitoring.
#
# Everything a campaign writes stays in OUT, including Renode/dotnet
# temporary files (TMPDIR=OUT/tmp), so long campaigns do not fill /tmp.

set -e

here=$(dirname "$(readlink -f "$0")")
afl_root=$(readlink -f "$here/../..")
resc=$afl_root/renode_mode/example-syscall.resc

usage() {
    sed -n '4,36s/^# \{0,1\}//p' "$0" >&2
    exit 1
}

# afl-fuzz pid of an instance, if it is still running
instance_pid() {
    local f=$1/$2.pid pid
    [ -f "$f" ] || return 1
    pid=$(cat "$f")
    [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q afl-fuzz &&
        echo "$pid"
}

start_instance() {        # OUT GROUP NAME resume
    local out=$1 group=$2 name=$3 resume=$4 dir=$1/$2 role input left
    # shellcheck source=/dev/null
    . "$out/campaign.conf"
    left=$((deadline - $(date +%s)))
    if [ "$left" -le 0 ]; then
        echo "$group/$name: campaign time is over" >&2
        return 1
    fi
    if [ "$name" = main ]; then role=(-M main); else role=(-S "$name"); fi
    if [ "$resume" = 1 ]; then input=-; else input=$(cat "$dir/seeds"); fi
    local cmd=(env TMPDIR=$out/tmp AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_SKIP_BIN_CHECK=1
         AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_FORKSRV_INIT_TMOUT=600000
         AFL_RENODE_COVERAGE=$coverage AFL_RENODE_CRASH_INFO=$dir/crash-info
         "$afl_root/afl-fuzz" -V "$left" -t 15000 -i "$input" -o "$dir/afl" "${role[@]}"
         -R -- "$resc" "$dir/zephyr.elf")
    if [ -n "$dry" ]; then
        echo "(cd $afl_root && setsid ${cmd[*]} >> $dir/$name.log 2>&1 &)"
        return 0
    fi
    echo "=== $(date '+%F %T') start ($([ "$resume" = 1 ] && echo resume || echo new), ${left}s)" >>"$dir/$name.log"
    (cd "$afl_root" && exec setsid "${cmd[@]}") </dev/null >>"$dir/$name.log" 2>&1 &
    echo $! >"$dir/$name.pid"
}

status() {                # OUT
    local out=$1 group name pid st
    while read -r group name; do
        pid=$(instance_pid "$out/$group" "$name") || pid=-
        st=$out/$group/afl/$name/fuzzer_stats
        if [ ! -f "$st" ]; then
            printf "%-14s %-5s pid %-8s (no stats yet)\n" "$group" "$name" "$pid"
            continue
        fi
        awk -v g="$group" -v i="$name" -v p="$pid" -F' *: ' '
            { v[$1] = $2 }
            END { printf "%-14s %-5s pid %-8s execs %-9s exec/s %-7s corpus %-5s stability %-8s crashes %s hangs %s\n",
                  g, i, p, v["execs_done"], v["execs_per_sec"], v["corpus_count"],
                  v["stability"], v["saved_crashes"], v["saved_hangs"] }' "$st"
    done <"$out/instances"
}

running() {               # OUT
    local group name
    while read -r group name; do
        instance_pid "$1/$group" "$name" >/dev/null && return 0
    done <"$1/instances"
    return 1
}

secs=600
jobs=1
out=${ZFUZZ_CAMPAIGNS:-$HOME/zfuzz}/$(date +%Y%m%d-%H%M)
coverage=window
dry=""
wait=""
mode=start
while getopts "d:j:o:c:nwR:S:K:h" opt; do
    case $opt in
    d) secs=$OPTARG ;;
    j) jobs=$OPTARG ;;
    o) out=$OPTARG ;;
    c) coverage=$OPTARG ;;
    n) dry=echo ;;
    w) wait=1 ;;
    R) mode=restart; out=$OPTARG ;;
    S) mode=status; out=$OPTARG ;;
    K) mode=stop; out=$OPTARG ;;
    *) usage ;;
    esac
done
shift $((OPTIND - 1))

if [ "$mode" != start ]; then
    out=$(readlink -f "$out")
    [ -f "$out/campaign.conf" ] || { echo "$out: not a campaign directory" >&2; exit 1; }
fi
case $mode in
status)
    status "$out"
    exit 0 ;;
stop)
    while read -r group name; do
        pid=$(instance_pid "$out/$group" "$name") && kill "$pid" && echo "stopped $group/$name ($pid)"
    done <"$out/instances"
    exit 0 ;;
restart)
    [ $# -ge 1 ] || usage
    for inst in "$@"; do
        group=${inst%/*}
        name=${inst#*/}
        grep -qx "$group $name" "$out/instances" || { echo "no instance $inst" >&2; exit 1; }
        if pid=$(instance_pid "$out/$group" "$name"); then
            echo "$inst is running ($pid)" >&2
            continue
        fi
        start_instance "$out" "$group" "$name" 1 && echo "restarted $inst ($(cat "$out/$group/$name.pid"))"
    done
    exit 0 ;;
esac

[ $# -ge 1 ] || usage
[ -e "$out" ] && { echo "$out already exists" >&2; exit 1; }
mkdir -p "$out"
out=$(readlink -f "$out")
case $out/ in
/tmp/*) echo "warning: $out is under /tmp, which may fill up during long campaigns" >&2 ;;
esac
# Renode and dotnet put scratch files (~1 MB per Renode instance, not always
# removed), crash dumps, pipes and Unix sockets in TMPDIR. Socket paths are
# limited to 107 bytes and dotnet appends ~45, so keep TMPDIR short.
if [ ${#out} -gt 56 ]; then
    echo "$out/tmp: too long for TMPDIR (max 60 chars), use a shorter -o" >&2
    exit 1
fi
mkdir -p "$out/tmp"
cat >"$out/campaign.conf" <<CONF
deadline=$(($(date +%s) + secs))
coverage=$coverage
CONF
: >"$out/instances"

for spec in "$@"; do
    group=${spec%%=*}
    elf=${spec#*=}
    [ "$group" != "$spec" ] && [ -f "$elf" ] || { echo "bad GROUP=ELF: $spec" >&2; exit 1; }
    [ -f "$elf.cov" ] || { echo "$elf.cov missing (build with this app's CMakeLists.txt)" >&2; exit 1; }
    seeds=$here/seeds/${group%%-*}
    [ -d "$seeds" ] || { echo "no seeds in $seeds" >&2; exit 1; }

    dir=$out/$group
    mkdir -p "$dir/crash-info"
    cp "$elf" "$dir/zephyr.elf"
    cp "$elf.cov" "$dir/zephyr.elf.cov"
    cfg=$(dirname "$elf")/.config
    [ -f "$cfg" ] && cp "$cfg" "$dir/zephyr.config"
    echo "$seeds" >"$dir/seeds"

    for i in $(seq 0 $((jobs - 1))); do
        if [ "$i" -eq 0 ]; then name=main; else name=s$i; fi
        echo "$group $name" >>"$out/instances"
        start_instance "$out" "$group" "$name" 0
    done
done

if [ -n "$dry" ]; then
    rm -rf "$out"
    exit 0
fi
echo "campaign in $out: $(wc -l <"$out/instances") instances for ${secs}s"
[ -n "$wait" ] || exit 0
while running "$out"; do sleep 10; done
status "$out"
