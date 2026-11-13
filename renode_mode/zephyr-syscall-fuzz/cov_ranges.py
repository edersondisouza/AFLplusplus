#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
'''
Writes the address ranges of the harness's own code (functions from source
files under SRC_DIR, inlined callees included) as "start end name" lines.
afl_syscall.py leaves these out of the AFL coverage map, so that only kernel
code drives corpus growth.

  cov_ranges.py ZEPHYR_ELF SRC_DIR OUTPUT
'''

import os
import sys

from elftools.elf.elffile import ELFFile


def high_pc(die, low):
    attr = die.attributes["DW_AT_high_pc"]
    # DWARF 4+: high_pc is usually an offset from low_pc
    return low + attr.value if attr.form != "DW_FORM_addr" else attr.value


def main():
    elf_path, src_dir, out_path = sys.argv[1:4]
    src_dir = os.path.realpath(src_dir)
    ranges = []
    with open(elf_path, "rb") as f:
        dwarf = ELFFile(f).get_dwarf_info()
        for cu in dwarf.iter_CUs():
            top = cu.get_top_DIE()
            name = top.attributes.get("DW_AT_name")
            comp_dir = top.attributes.get("DW_AT_comp_dir")
            if name is None:
                continue
            path = name.value.decode()
            if comp_dir is not None and not os.path.isabs(path):
                path = os.path.join(comp_dir.value.decode(), path)
            if not os.path.realpath(path).startswith(src_dir + os.sep):
                continue
            for die in cu.iter_DIEs():
                if (die.tag == "DW_TAG_subprogram" and "DW_AT_low_pc" in die.attributes
                        and "DW_AT_high_pc" in die.attributes):
                    low = die.attributes["DW_AT_low_pc"].value
                    fn = die.attributes.get("DW_AT_name")
                    ranges.append((low, high_pc(die, low),
                                   fn.value.decode() if fn else "?"))
    if not ranges:
        sys.exit("cov_ranges.py: no functions found under %s" % src_dir)
    with open(out_path, "w") as f:
        for low, high, fn in sorted(ranges):
            f.write("%#x %#x %s\n" % (low, high, fn))


if __name__ == "__main__":
    main()
