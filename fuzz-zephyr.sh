#!/bin/bash

# This script is used to fuzz Zephyr applications using AFL++.
# Usage: ./fuzz-zephyr.sh <zephyr_elf_files_directory> <testcases_directory>

set -x

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="/tmp/afl_renode_output"
    echo "OUTPUT_DIR is not set, using default: $OUTPUT_DIR"
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
fi

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <zephyr_elf_files_directory> <testcases_directory>"
    exit 1
fi

# Loop over all ELF files in the specified directory
ELFS=("$1"/*.elf)

if [ -z "$ELFS" ]; then
    echo "No ELF files found in the directory: $1"
    exit 1
fi

NR_ELFS=${#ELFS[@]}
NR_CORES=$(nproc --all)

RATIO=$((NR_CORES / NR_ELFS))

for elf_file in ${ELFS[@]}; do
    echo "Processing ELF file: $elf_file"

    # Use readelf to get location of k_sys_fatal_error_handler
    K_SYS_FATAL_ERROR_HANDLER=$(readelf -sW "$elf_file" | grep k_sys_fatal_error_handler | awk '{ print "0x"$2  }' | awk --non-decimal-data '{ printf "0x%x\n", $1-1 }')
    if [ -z "$K_SYS_FATAL_ERROR_HANDLER" ]; then
        echo "k_sys_fatal_error_handler not found in the ELF file."
        exit 1
    fi

    # Create temp dir for this elf file output
    temp_dir=$(mktemp -d "$OUTPUT_DIR/$(basename -s .elf $elf_file)_XXXXXX")

    echo "Temporary directory created: $temp_dir"

    # If RATIO > 1, run AFL++ in parallel
    if [ $RATIO -gt 1 ]; then
        echo "Running AFL++ in parallel for $elf_file with RATIO: $RATIO"

        # Main instance
        AFL_K_SYS_FATAL_HANDLER_LOC="$K_SYS_FATAL_ERROR_HANDLER" AFL_SKIP_CPUFREQ=1 AFL_SKIP_BIN_CHECK=1 AFL_NO_UI=1 \
        ./afl-fuzz -M fuzzer01 -D -t 15000 -i $2 -o $temp_dir -R -- renode_mode/example-mem.resc $elf_file &

        # Additional instances
        for i in $(seq 2 $RATIO); do
            AFL_K_SYS_FATAL_HANDLER_LOC="$K_SYS_FATAL_ERROR_HANDLER" AFL_SKIP_CPUFREQ=1 AFL_SKIP_BIN_CHECK=1 AFL_NO_UI=1 \
            ./afl-fuzz -S "fuzzer$i" -D -t 15000 -i $2 -o $temp_dir -R -- renode_mode/example-mem.resc $elf_file &
        done
    else
        echo "Running single AFL++ for $elf_file"
        AFL_K_SYS_FATAL_HANDLER_LOC="$K_SYS_FATAL_ERROR_HANDLER" AFL_SKIP_CPUFREQ=1 AFL_SKIP_BIN_CHECK=1 AFL_NO_UI=1 \
            ./afl-fuzz -D -t 15000 -i $2 -o $temp_dir -R -- renode_mode/example-mem.resc $elf_file &
    fi
done
