#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Watch a campaign started by campaign.sh and exit when it needs attention.

  watchdog.py [options] OUT

Every --interval seconds, samples each instance (afl-fuzz alive, Renode RSS,
fuzzer_stats) into OUT/metrics.csv and checks for:

  dead       afl-fuzz exited before the end of the campaign (e.g. Renode
             crashed: afl-fuzz aborts when its fork server goes away)
  mem        Renode RSS above --rss-mb
  memgrowth  Renode RSS grew more than --rss-growth-mb since first seen
  slow       execs_ps_last_min below --min-eps for --slow-samples samples
  stall      fuzzer_stats not updated for --stall seconds
  crash/hang new files in crashes/ or hangs/ (with their crash record)
  disk       less than --disk-gb free for OUT or --tmp-disk-gb for /tmp
  supervisor a new line in OUT/actions.log, or no supervisor running

While the supervisor (--supervise, started by campaign.sh) runs, it handles
dead and stalled instances itself, so those are reported only through its
actions (restart, kill, gave up).

Each event is reported once: its key is appended to OUT/watchdog.ack and
the event to OUT/events.log. Exit status:

  0  campaign over (no instance left running), final status printed
  3  new events, printed on stdout; fix what is needed and run again
  4  periodic report (--report-hours), for trends such as slow memory creep

To stop watching an instance that will not be restarted, touch
OUT/<GROUP>/<INSTANCE>.retired.
"""

import argparse
import collections
import csv
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import time


def read_kv(path, sep):
    kv = {}
    try:
        with open(path) as f:
            for line in f:
                if sep in line:
                    k, v = line.split(sep, 1)
                    kv[k.strip()] = v.strip()
    except OSError:
        pass
    return kv


def afl_alive(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return b"afl-fuzz" in f.read()
    except OSError:
        return False


def children(pid):
    out = []
    try:
        for tid in os.listdir(f"/proc/{pid}/task"):
            with open(f"/proc/{pid}/task/{tid}/children") as f:
                out += [int(c) for c in f.read().split()]
    except OSError:
        pass
    return out


def renode_pid(pid):
    todo = children(pid)
    while todo:
        p = todo.pop()
        try:
            with open(f"/proc/{p}/comm") as f:
                if f.read().strip() == "dotnet":
                    return p
        except OSError:
            continue
        todo += children(p)
    return None


def rss_mb(pid):
    st = read_kv(f"/proc/{pid}/status", ":")
    try:
        return int(st["VmRSS"].split()[0]) // 1024
    except (KeyError, ValueError):
        return None


def tail(path, n):
    try:
        with open(path, errors="replace") as f:
            lines = [l.rstrip() for l in f if l.strip()]
    except OSError:
        return []
    return lines[-n:]


def crash_summary(group_dir, path):
    with open(path, "rb") as f:
        sha = hashlib.sha1(f.read()).hexdigest()
    rec = os.path.join(group_dir, "crash-info", sha + ".txt")
    info = read_kv(rec, ":")
    if not info:
        return "(no crash record)", rec
    if "assert" in info:
        sig = f"assert {info['assert']}"
    else:
        sig = f"{info.get('reason', '?')} at {info.get('pc', '?').split(' ', 1)[-1]}"
    return sig, rec


class Watchdog:
    def __init__(self, args):
        self.a = args
        self.out = os.path.abspath(args.out)
        conf = read_kv(os.path.join(self.out, "campaign.conf"), "=")
        if "deadline" not in conf:
            sys.exit(f"{self.out}: not a campaign directory")
        self.deadline = int(conf["deadline"])
        self.ack_path = os.path.join(self.out, "watchdog.ack")
        try:
            with open(self.ack_path) as f:
                self.acked = set(l.rstrip("\n") for l in f)
        except OSError:
            self.acked = set()
        self.first_rss = {}
        self.slow = collections.Counter()
        self.metrics = os.path.join(self.out, "metrics.csv")
        if not os.path.exists(self.metrics):
            with open(self.metrics, "w") as f:
                f.write("time,group,instance,afl_pid,alive,renode_pid,rss_mb,execs_done,"
                        "eps_last_min,corpus,crashes,hangs,stability,load1,free_out_gb,free_tmp_gb\n")

    def instances(self):
        with open(os.path.join(self.out, "instances")) as f:
            for line in f:
                if line.strip():
                    g, n = line.split()
                    yield g, n

    def sample(self, events):
        a, now = self.a, time.time()
        load1 = os.getloadavg()[0]
        free_out = shutil.disk_usage(self.out).free / 2**30
        free_tmp = shutil.disk_usage("/tmp").free / 2**30
        if free_out < a.disk_gb:
            events.append(("disk out", f"disk: only {free_out:.1f} GB free for {self.out}", []))
        if free_tmp < a.tmp_disk_gb:
            events.append(("disk tmp", f"disk: only {free_tmp:.1f} GB free in /tmp", []))
        alive_any = False
        rows = []
        crashes = collections.defaultdict(list)
        supervised, sup_pid = supervisor_alive(self.out)
        if supervised:
            try:
                with open(os.path.join(self.out, "actions.log")) as f:
                    for line in f:
                        line = line.rstrip("\n")
                        events.append((f"action {line}", f"supervisor: {line}", []))
            except OSError:
                pass
        elif now < self.deadline - 2 * a.interval:
            events.append((f"nosupervisor {sup_pid}",
                           "supervisor: not running, dead instances will not be restarted "
                           "(campaign.sh -P OUT)", []))
        for g, n in self.instances():
            gdir = os.path.join(self.out, g)
            inst = f"{g}/{n}"
            if os.path.exists(os.path.join(gdir, n + ".retired")):
                continue
            try:
                with open(os.path.join(gdir, n + ".pid")) as f:
                    pid = int(f.read())
            except (OSError, ValueError):
                pid = 0
            alive = pid > 0 and afl_alive(pid)
            adir = os.path.join(gdir, "afl", n)
            st = read_kv(os.path.join(adir, "fuzzer_stats"), ":")
            rpid = rss = None
            if alive:
                alive_any = True
                rpid = renode_pid(pid)
                if rpid:
                    rss = rss_mb(rpid)
                if rss is not None:
                    self.first_rss.setdefault(rpid, rss)
                    if rss > a.rss_mb:
                        events.append((f"mem {inst} {rpid}",
                                       f"mem: {inst} Renode {rpid} RSS {rss} MB > {a.rss_mb} MB", []))
                    grow = rss - self.first_rss[rpid]
                    if grow > a.rss_growth_mb:
                        events.append((f"memgrowth {inst} {rpid}",
                                       f"memgrowth: {inst} Renode {rpid} RSS grew {grow} MB "
                                       f"({self.first_rss[rpid]} -> {rss} MB)", []))
                if st:
                    age = now - int(st.get("last_update", now))
                    if age > a.stall and not supervised:
                        events.append((f"stall {inst} {pid}",
                                       f"stall: {inst} fuzzer_stats not updated for {age:.0f}s", []))
                    eps = float(st.get("execs_ps_last_min", st.get("execs_per_sec", 0)))
                    if int(st.get("run_time", 0)) > a.warmup and eps < a.min_eps:
                        self.slow[pid] += 1
                        if self.slow[pid] >= a.slow_samples:
                            events.append((f"slow {inst} {pid}",
                                           f"slow: {inst} {eps} exec/s (last min), load {load1:.1f}", []))
                    else:
                        self.slow[pid] = 0
            elif now < self.deadline - 2 * a.interval and not supervised:
                events.append((f"dead {inst} {pid}", f"dead: {inst} afl-fuzz {pid} exited "
                               f"{(self.deadline - now) / 3600:.1f} h before the end",
                               tail(os.path.join(gdir, n + ".log"), 6)))
            ncrash = nhang = 0
            for kind in ("crashes", "hangs"):
                d = os.path.join(adir, kind)
                try:
                    files = sorted(f for f in os.listdir(d) if f.startswith("id:"))
                except OSError:
                    files = []
                if kind == "crashes":
                    ncrash = len(files)
                else:
                    nhang = len(files)
                for f in files:
                    key = f"{kind} {inst} {f}"
                    if key in self.acked:
                        continue
                    path = os.path.join(d, f)
                    sig, rec = crash_summary(gdir, path)
                    crashes[(kind, g, sig)].append((key, path, rec))
            rows.append([int(now), g, n, pid, int(alive), rpid or "", rss if rss is not None else "",
                         st.get("execs_done", ""), st.get("execs_ps_last_min", ""),
                         st.get("corpus_count", ""), ncrash, nhang, st.get("stability", ""),
                         f"{load1:.1f}", f"{free_out:.1f}", f"{free_tmp:.1f}"])
        for (kind, g, sig), items in crashes.items():
            keys = [k for k, _, _ in items]
            _, path, rec = items[0]
            events.append((keys, f"{kind[:-1] if kind == 'hangs' else 'crash'}: {g} {len(items)} new, "
                           f"{sig}", [f"example: {path}", f"record:  {rec}"]))
        with open(self.metrics, "a", newline="") as f:
            csv.writer(f).writerows(rows)
        return alive_any

    def report(self, title):
        print(f"== {title} {time.strftime('%F %T')}, "
              f"{max(0, self.deadline - time.time()) / 3600:.1f} h left")
        for g, n in self.instances():
            st = read_kv(os.path.join(self.out, g, "afl", n, "fuzzer_stats"), ":")
            print(f"  {g + '/' + n:20} execs {st.get('execs_done', '-'):>9} "
                  f"exec/s {st.get('execs_ps_last_min', '-'):>6} corpus {st.get('corpus_count', '-'):>5} "
                  f"stab {st.get('stability', '-'):>8} crashes {st.get('saved_crashes', '-')} "
                  f"hangs {st.get('saved_hangs', '-')}")
        for rpid, first in self.first_rss.items():
            now = rss_mb(rpid)
            if now is not None:
                print(f"  Renode {rpid}: RSS {first} -> {now} MB")

    def run(self):
        a = self.a
        start = time.time()
        print(f"watchdog: {self.out}, {(self.deadline - start) / 3600:.1f} h left", flush=True)
        while True:
            events = []
            alive = self.sample(events)
            new = []
            for key, msg, detail in events:
                keys = key if isinstance(key, list) else [key]
                if all(k in self.acked for k in keys):
                    continue
                new.append((keys, msg, detail))
            if new:
                stamp = time.strftime("%F %T")
                with open(os.path.join(self.out, "events.log"), "a") as log, \
                        open(self.ack_path, "a") as ack:
                    for keys, msg, detail in new:
                        print(msg)
                        for d in detail:
                            print("    " + d)
                        log.write(f"{stamp} {msg}\n")
                        for k in keys:
                            ack.write(k + "\n")
                            self.acked.add(k)
                self.report("status")
                return 3
            if not alive:
                self.report("campaign over")
                return 0
            if a.report_hours and time.time() - start >= a.report_hours * 3600:
                self.report("periodic report")
                return 4
            time.sleep(a.interval)


class Supervisor(Watchdog):
    '''Keeps a campaign running unattended until its deadline.

    Restarts instances that died (at most --max-restarts per instance per
    hour) and SIGKILLs a Renode whose heartbeat file is older than --stall
    seconds, so that its afl-fuzz exits and is restarted. Every action is
    appended to OUT/actions.log, which the reporting watchdog turns into
    events.'''

    def act(self, msg, detail=()):
        line = f"{time.strftime('%F %T')} {msg}"
        print(line, flush=True)
        for d in detail:
            print("    " + d, flush=True)
        with open(os.path.join(self.out, "actions.log"), "a") as f:
            f.write(line + "\n")

    def run(self):
        a = self.a
        campaign = os.path.join(os.path.dirname(os.path.abspath(__file__)), "campaign.sh")
        restarts = collections.defaultdict(list)
        given_up = set()
        self.act(f"supervisor {os.getpid()} up, {(self.deadline - time.time()) / 3600:.1f} h left")
        while True:
            now = time.time()
            alive_any = False
            for g, n in self.instances():
                gdir = os.path.join(self.out, g)
                inst = f"{g}/{n}"
                if os.path.exists(os.path.join(gdir, n + ".retired")):
                    continue
                pidfile = os.path.join(gdir, n + ".pid")
                try:
                    with open(pidfile) as f:
                        pid = int(f.read())
                    started = os.path.getmtime(pidfile)
                except (OSError, ValueError):
                    continue
                if afl_alive(pid):
                    alive_any = True
                    try:
                        beat = os.path.getmtime(os.path.join(gdir, n + ".alive"))
                    except OSError:
                        beat = 0
                    age = now - max(beat, started)
                    rpid = renode_pid(pid)
                    if age > a.stall and rpid:
                        try:
                            os.kill(rpid, signal.SIGKILL)
                            self.act(f"killed {inst} Renode {rpid}: no heartbeat for {age:.0f}s")
                        except OSError as e:
                            self.act(f"cannot kill {inst} Renode {rpid}: {e}")
                    continue
                if now >= self.deadline - 2 * a.interval or inst in given_up:
                    continue
                recent = [t for t in restarts[inst] if now - t < 3600]
                restarts[inst] = recent
                log = tail(os.path.join(gdir, n + ".log"), 3)
                if len(recent) >= a.max_restarts:
                    given_up.add(inst)
                    self.act(f"gave up on {inst}: {len(recent)} restarts in the last hour", log)
                    continue
                r = subprocess.run([campaign, "-R", self.out, inst],
                                   capture_output=True, text=True)
                restarts[inst].append(now)
                self.act(f"restart {inst} (afl-fuzz {pid} died): "
                         f"{(r.stdout + r.stderr).strip() or r.returncode}", log)
                alive_any = True
            if not alive_any and now >= self.deadline - 2 * a.interval:
                self.act("supervisor done: campaign over")
                return 0
            time.sleep(a.interval)


def supervisor_alive(out):
    try:
        with open(os.path.join(out, "supervisor.pid")) as f:
            pid = int(f.read())
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return b"--supervise" in f.read(), pid
    except (OSError, ValueError):
        return False, None


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("out")
    p.add_argument("--interval", type=int, default=60, help="seconds between samples (60)")
    p.add_argument("--rss-mb", type=int, default=2048, help="Renode RSS limit (2048)")
    p.add_argument("--rss-growth-mb", type=int, default=512,
                   help="Renode RSS growth limit since first seen (512)")
    p.add_argument("--min-eps", type=float, default=15, help="minimum exec/s (15)")
    p.add_argument("--slow-samples", type=int, default=3,
                   help="consecutive slow samples before reporting (3)")
    p.add_argument("--warmup", type=int, default=600,
                   help="instance run time before checking exec/s (600)")
    p.add_argument("--stall", type=int, default=600,
                   help="seconds without a fuzzer_stats update (600)")
    p.add_argument("--disk-gb", type=float, default=5, help="minimum free GB for OUT (5)")
    p.add_argument("--tmp-disk-gb", type=float, default=2, help="minimum free GB in /tmp (2)")
    p.add_argument("--report-hours", type=float, default=0,
                   help="exit with a status report after this many hours (off)")
    p.add_argument("--supervise", action="store_true",
                   help="run as the campaign supervisor instead (see campaign.sh)")
    p.add_argument("--max-restarts", type=int, default=5,
                   help="supervisor: restarts per instance per hour before giving up (5)")
    args = p.parse_args()
    sys.exit((Supervisor if args.supervise else Watchdog)(args).run())


if __name__ == "__main__":
    main()
