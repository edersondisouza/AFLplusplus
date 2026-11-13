# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(syscall_fuzz)

target_sources(app PRIVATE src/main.c)

# Harness code ranges, excluded from AFL coverage (see cov_ranges.py)
set(cov_ranges ${ZEPHYR_BINARY_DIR}/${KERNEL_ELF_NAME}.cov)
add_custom_command(OUTPUT ${cov_ranges}
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/cov_ranges.py
          ${ZEPHYR_BINARY_DIR}/${KERNEL_ELF_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${cov_ranges}
  DEPENDS ${ZEPHYR_BINARY_DIR}/${KERNEL_ELF_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/cov_ranges.py
)
add_custom_target(syscall_fuzz_cov_ranges ALL DEPENDS ${cov_ranges})
add_dependencies(syscall_fuzz_cov_ranges ${logical_target_for_zephyr_elf})
