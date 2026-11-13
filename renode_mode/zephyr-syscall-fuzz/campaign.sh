#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run fuzzing campaigns for one or more syscall groups, in parallel.
#
#   campaign.sh [-d SECS] [-j JOBS] [-o OUT] [-c COVERAGE] [-n] GROUP=ELF...
#
#   GROUP=ELF  campaign name and zephyr.elf built for it, e.g.
#              objects=../build-g-objects/zephyr/zephyr.elf
#              Seeds come from seeds/<GROUP up to the first '-'>, so
#              futex-kmutex=... uses seeds/futex.
#   -d SECS    duration of every instance (default 600)
#   -j JOBS    afl-fuzz instances per group: one -M plus JOBS-1 -S (default 1)
#   -o OUT     output directory (default
#              ${ZFUZZ_CAMPAIGNS:-$HOME/zfuzz}/<date>)
#   -c MODE    AFL_RENODE_COVERAGE: window (default), kernel or all
#   -n         print the commands instead of running them
#
# The ELF and its .cov are copied to OUT/<GROUP>/ and fuzzed from there, so
# rebuilding during a campaign does not affect it, and crashes can later be
# replayed against the exact binary (see replay.sh). Every instance writes
# OUT/<GROUP>/<instance>.log and crash records to OUT/<GROUP>/crash-info/.
# Run from anywhere; afl-fuzz is taken from the root of this AFL++ tree.
#
# Everything a campaign writes stays in OUT, including Renode/dotnet
# temporary files (TMPDIR=OUT/tmp), so long campaigns do not fill /tmp.

set -e

here=$(dirname "$(readlink -f "$0")")
afl_root=$(readlink -f "$here/../..")
resc=$afl_root/renode_mode/example-syscall.resc

usage() {
    sed -n '4,26s/^# \{0,1\}//p' "$0" >&2
    exit 1
}

secs=600
jobs=1
out=${ZFUZZ_CAMPAIGNS:-$HOME/zfuzz}/$(date +%Y%m%d-%H%M)
coverage=window
dry=""
while getopts "d:j:o:c:nh" opt; do
    case $opt in
    d) secs=$OPTARG ;;
    j) jobs=$OPTARG ;;
    o) out=$OPTARG ;;
    c) coverage=$OPTARG ;;
    n) dry=echo ;;
    *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || usage

mkdir -p "$out"
out=$(readlink -f "$out")
case $out/ in
/tmp/*) echo "warning: $out is under /tmp, which may fill up during long campaigns" >&2 ;;
esac
# Renode and dotnet put scratch files (~1 MB per Renode instance, not always
# removed), crash dumps, pipes and Unix sockets in TMPDIR. Socket paths are
# limited to 107 bytes and dotnet appends ~45, so keep TMPDIR short.
tmp=$out/tmp
if [ ${#tmp} -gt 60 ]; then
    echo "$tmp: too long for TMPDIR (max 60 chars), use a shorter -o" >&2
    exit 1
fi
mkdir -p "$tmp"
pids=()

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

    for i in $(seq 0 $((jobs - 1))); do
        if [ "$i" -eq 0 ]; then role="-M main"; name=main; else role="-S s$i"; name=s$i; fi
        cmd=(env TMPDIR=$tmp AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_SKIP_BIN_CHECK=1
             AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_FORKSRV_INIT_TMOUT=600000
             AFL_RENODE_COVERAGE=$coverage AFL_RENODE_CRASH_INFO=$dir/crash-info
             "$afl_root/afl-fuzz" -V "$secs" -t 15000 -i "$seeds" -o "$dir/afl" $role
             -R -- "$resc" "$dir/zephyr.elf")
        if [ -n "$dry" ]; then
            echo "(cd $afl_root && ${cmd[*]} > $dir/$name.log 2>&1 &)"
        else
            (cd "$afl_root" && exec "${cmd[@]}") > "$dir/$name.log" 2>&1 &
            pids+=($!)
        fi
    done
done

[ -n "$dry" ] && exit 0
echo "campaign in $out: ${#pids[@]} instances for ${secs}s (pids ${pids[*]})"
trap 'kill "${pids[@]}" 2>/dev/null' INT TERM
wait "${pids[@]}" || true

for spec in "$@"; do
    group=${spec%%=*}
    for st in "$out/$group"/afl/*/fuzzer_stats; do
        [ -f "$st" ] || continue
        awk -v g="$group" -v i="$(basename "$(dirname "$st")")" -F' *: ' '
            { v[$1] = $2 }
            END { printf "%-14s %-5s execs %-8s exec/s %-7s corpus %-5s stability %-8s crashes %s hangs %s\n",
                  g, i, v["execs_done"], v["execs_per_sec"], v["corpus_count"],
                  v["stability"], v["saved_crashes"], v["saved_hangs"] }' "$st"
    done
done
