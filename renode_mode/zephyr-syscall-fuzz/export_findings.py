#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Collect the findings of a campaign.sh campaign into a self-contained
directory for triage by someone else:

  export_findings.py [-j N] [--no-replay] CAMPAIGN_DIR BUNDLE_DIR

For each group (CAMPAIGN_DIR/<group>/ with afl/, crash-info/, zephyr.elf):
  - every distinct input AFL saved under afl/*/crashes, as inputs/<sha1>,
    with its crash record crash-info/<sha1>.txt (written by afl_syscall.py)
  - a signature per input: for bugs the fatal reason and the functions of
    pc and lr (and the assertion), for hangs the op the run was stuck in
  - every input replayed with replay.sh -t: the index says how many ended
    the same way, hangs whose trace shows the input stream rewinding (a
    syscall overwrote the workers' input position) get their own signatures,
    and traces/<sig>.txt keeps the trace of each signature's smallest input
    (ops each worker executed, and the outcome)
  - index.md / index.csv, zephyr.elf and zephyr.config

BUNDLE_DIR/README.md is written by hand (see the first export), this script
only writes a stub if it is missing. Triage notes in BUNDLE_DIR/notes.csv
(columns group, signature, note) go into the note column of the indexes.
"""

import argparse
import csv
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from bisect import bisect_right
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
REPLAY = os.path.join(HERE, "replay.sh")


def elf_symtab(path):
    with open(path, "rb") as f:
        data = f.read()
    shoff, = struct.unpack_from("<I", data, 32)
    shentsize, shnum = struct.unpack_from("<HH", data, 46)
    shdrs = [struct.unpack_from("<10I", data, shoff + i * shentsize) for i in range(shnum)]
    for sh in shdrs:
        if sh[1] != 2:
            continue
        stroff = shdrs[sh[6]][4]
        for off in range(sh[4], sh[4] + sh[5], 16):
            st_name, value, size, info, _, shndx = struct.unpack_from("<IIIBBH", data, off)
            end = data.index(b"\0", stroff + st_name)
            yield value, size, info & 0xf, shndx, data[stroff + st_name:end].decode()


class Elf:
    def __init__(self, path):
        self.funcs = []
        self.conf = {}
        for value, size, typ, shndx, name in elf_symtab(path):
            if shndx == 0xfff1 and name.startswith("CONFIG_"):
                self.conf[name] = value
            elif typ in (1, 2) and value and shndx not in (0, 0xfff1):
                self.funcs.append((value & ~1 if typ == 2 else value, size, name))
        self.funcs.sort()
        groups = [n[len("CONFIG_SYSCALL_FUZZ_GROUP_"):].lower() for n in self.conf
                  if n.startswith("CONFIG_SYSCALL_FUZZ_GROUP_")]
        self.group = groups[0] if len(groups) == 1 else None
        self.ops = []
        if self.group:
            with open(os.path.join(SRC, "group_%s.c" % self.group)) as f:
                m = re.search(r"enum (?:fz_)?op \{([^}]*)\}", f.read())
            if m:
                self.ops = [n.strip()[3:] for n in m.group(1).split(",") if n.strip()]
                if "COUNT" in self.ops:
                    self.ops = self.ops[:self.ops.index("COUNT")]

    def func(self, addr):
        a = addr & ~1
        i = bisect_right(self.funcs, (a, 0xFFFFFFFF, "")) - 1
        while i >= 0 and self.funcs[i][0] > a - 0x10000:
            start, size, name = self.funcs[i]
            if a < start + max(size, 1):
                return name
            i -= 1
        return "?"

    def op(self, byte):
        return self.ops[byte % len(self.ops)] if self.ops else "%#x" % byte


def parse_record(text):
    rec = {}
    for line in text.splitlines():
        key, _, val = line.partition(": ")
        if key in ("status", "reason", "thread", "pc", "lr", "assert", "last op", "hang"):
            rec[key] = val
    return rec


def first_hex(s):
    m = re.match(r"\s*(0x[0-9a-fA-F]+)", s or "")
    return int(m.group(1), 16) if m else None


def signature(rec, elf):
    if not rec:
        return "no crash record"
    if "reason" not in rec:
        return "host watchdog %s (no guest record)" % (
            "hang" if rec.get("status", "").startswith("14") else "failure")
    last = re.match(r"(0x[0-9a-f]+) at input offset", rec.get("last op", ""))
    last_op = elf.op(int(last.group(1), 16)) if last else "?"
    if rec.get("status", "").startswith("14"):
        return "hang, last op %s" % last_op
    reason = re.search(r"\((\w+)\)", rec.get("reason", ""))
    reason = reason.group(1) if reason else rec.get("reason", "?")
    sig = reason
    if "pc" in rec:
        sig += " pc=%s lr=%s" % (elf.func(first_hex(rec["pc"])), elf.func(first_hex(rec["lr"])))
    if "assert" in rec:
        sig += " assert=%s" % rec["assert"].rsplit("/", 1)[-1]
    return sig


def same_outcome(orig, new):
    if not new:
        return "no outcome"
    if orig.get("status", "")[:2] != new.get("status", "")[:2]:
        return "differs: %s" % new.get("status", "?")
    for k in ("reason", "pc", "assert"):
        if first_hex(orig.get(k)) != first_hex(new.get(k)) or (
                k == "assert" and orig.get(k) != new.get(k)):
            return "differs: %s %s" % (k, new.get(k, "-"))
    return "yes"


def rewound(trace):
    with open(trace) as f:
        m = re.search(r"# stream rewound (\d+) times", f.read())
    return int(m.group(1)) if m else 0


def replay(elf_path, inp, trace, tmp):
    env = dict(os.environ, TMPDIR=tmp)
    try:
        subprocess.run([REPLAY, "-t", trace, elf_path, inp], env=env, timeout=600,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {}
    if not os.path.exists(trace):
        return {}
    with open(trace) as f:
        return parse_record(f.read().split("# outcome:\n", 1)[-1])


def load_notes(bundle):
    '''BUNDLE/notes.csv: "signature,note" rows, from earlier triage'''
    path = os.path.join(bundle, "notes.csv")
    if not os.path.exists(path):
        return {}
    with open(path, newline="") as f:
        return {(r["group"], r["signature"]): r["note"] for r in csv.DictReader(f)}


def export_group(name, src, dst, args, pool, tmp):
    elf = Elf(os.path.join(src, "zephyr.elf"))
    for d in ("inputs", "crash-info", "traces"):
        os.makedirs(os.path.join(dst, d), exist_ok=True)
    for f in ("zephyr.elf", "zephyr.config"):
        if os.path.exists(os.path.join(src, f)):
            shutil.copy2(os.path.join(src, f), dst)

    found = {}          # sha1 -> (input path, AFL file names)
    afl = os.path.join(src, "afl")
    for inst in sorted(os.listdir(afl)) if os.path.isdir(afl) else []:
        cdir = os.path.join(afl, inst, "crashes")
        if not os.path.isdir(cdir):
            continue
        for fn in sorted(os.listdir(cdir)):
            if not fn.startswith("id:"):
                continue
            p = os.path.join(cdir, fn)
            with open(p, "rb") as f:
                sha = hashlib.sha1(f.read()).hexdigest()
            found.setdefault(sha, [p, []])[1].append("%s/%s" % (inst, fn))

    recs = {}
    for sha, (p, _) in found.items():
        shutil.copy2(p, os.path.join(dst, "inputs", sha))
        ci = os.path.join(src, "crash-info", sha + ".txt")
        rec = {}
        if os.path.exists(ci):
            shutil.copy2(ci, os.path.join(dst, "crash-info"))
            with open(ci) as f:
                rec = parse_record(f.read())
        recs[sha] = rec

    # Replay every input: the outcome and the trace classify it better
    # than the crash record alone (e.g. hangs that rewound the stream)
    tdir = os.path.join(tmp, name)
    os.makedirs(tdir, exist_ok=True)
    jobs = {}
    if not args.no_replay:
        for sha in found:
            jobs[sha] = pool.submit(replay, os.path.join(dst, "zephyr.elf"),
                                    os.path.join(dst, "inputs", sha),
                                    os.path.join(tdir, sha + ".txt"), tmp)
    outcome = {}
    rewinds = {}
    for i, sha in enumerate(sorted(found)):
        if sha in jobs:
            outcome[sha] = same_outcome(recs[sha], jobs[sha].result())
            t = os.path.join(tdir, sha + ".txt")
            rewinds[sha] = rewound(t) if os.path.exists(t) else 0
        if (i + 1) % 200 == 0:
            print("  %s: %d/%d replayed" % (name, i + 1, len(found)), flush=True)

    sigs = defaultdict(list)
    for sha, (p, _) in found.items():
        sig = signature(recs[sha], elf)
        if rewinds.get(sha):
            sig = sig.replace("hang", "hang (stream rewound)", 1)
        sigs[sig].append((os.path.getsize(p), sha))

    order = sorted(sigs, key=lambda s: (s.startswith("hang"), -len(sigs[s]), s))
    rows = []
    for i, sig in enumerate(order, 1):
        sid = "%s-%02d" % (name, i)
        size, rep = min(sigs[sig])
        members = [sha for _, sha in sigs[sig]]
        repro = sum(outcome.get(sha) == "yes" for sha in members)
        row = dict(id=sid, count=len(members), signature=sig, representative=rep,
                   size=size, reproduces="%d/%d" % (repro, len(members)) if jobs
                   else "not replayed", note=args.notes.get((name, sig), ""))
        t = os.path.join(tdir, rep + ".txt")
        if os.path.exists(t):
            shutil.copy2(t, os.path.join(dst, "traces", sid + ".txt"))
        rows.append(row)
    sig_of = {sha: s for s, l in sigs.items() for _, sha in l}
    id_of = {r["signature"]: r["id"] for r in rows}

    with open(os.path.join(dst, "inputs.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sha1", "id", "signature", "replay", "rewinds", "afl_files"])
        for sha in sorted(found):
            w.writerow([sha, id_of[sig_of[sha]], sig_of[sha], outcome.get(sha, ""),
                        rewinds.get(sha, ""), " ".join(found[sha][1])])
    with open(os.path.join(dst, "index.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["id"])
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(dst, "index.md"), "w") as f:
        f.write("# %s: %d inputs, %d signatures\n\n" % (name, len(found), len(rows)))
        f.write("| id | inputs | signature | representative (bytes) | replay reproduces "
                "| note |\n|---|---|---|---|---|---|\n")
        for r in rows:
            f.write("| %s | %d | %s | %s (%d) | %s | %s |\n" % (
                r["id"], r["count"], r["signature"], r["representative"][:12],
                r["size"], r["reproduces"], r["note"]))
    return name, len(found), rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("campaign")
    ap.add_argument("bundle")
    ap.add_argument("-j", type=int, default=4, help="parallel replays")
    ap.add_argument("--no-replay", action="store_true")
    args = ap.parse_args()

    groups = sorted(g for g in os.listdir(args.campaign)
                    if os.path.exists(os.path.join(args.campaign, g, "zephyr.elf")))
    os.makedirs(args.bundle, exist_ok=True)
    args.notes = load_notes(args.bundle)
    tmp = tempfile.mkdtemp(prefix="export-", dir=os.path.join(args.bundle, ".."))
    summary = []
    with ThreadPoolExecutor(args.j) as pool:
        for g in groups:
            print("exporting %s" % g, flush=True)
            summary.append(export_group(g, os.path.join(args.campaign, g),
                                        os.path.join(args.bundle, g), args, pool, tmp))
    shutil.rmtree(tmp, ignore_errors=True)
    with open(os.path.join(args.bundle, "SUMMARY.md"), "w") as f:
        f.write("| group | inputs | signatures |\n|---|---|---|\n")
        for name, n, rows in summary:
            f.write("| %s | %d | %d |\n" % (name, n, len(rows)))
    if not os.path.exists(os.path.join(args.bundle, "README.md")):
        with open(os.path.join(args.bundle, "README.md"), "w") as f:
            f.write("See SUMMARY.md and <group>/index.md.\n")
    print(open(os.path.join(args.bundle, "SUMMARY.md")).read())


if __name__ == "__main__":
    sys.exit(main())
