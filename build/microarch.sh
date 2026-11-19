#!/bin/sh
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Prints the CPU level flag of an Odin build on this machine. Every build
# script and `make test` add its output to the compiler flags.
#
#   build/microarch.sh [machine]      machine: default `uname -m`
#
#   amd64   -microarch:x86-64-v3  (AVX2, BMI2, FMA: Intel Haswell of 2013,
#           AMD Excavator of 2015, and later)
#   other   nothing: the default of the compiler
#
# A program built for x86-64-v3 does not start on an older CPU. Environment:
#   NOIR_MICROARCH=x86-64-v2   a build for older amd64 CPUs (any value of
#                              `odin build -microarch:?` is accepted)
#   NOIR_MICROARCH=default     no flag: the default of the compiler
set -eu
machine=${1:-$(uname -m)}
level=${NOIR_MICROARCH:-}
case "$level" in
default) exit 0 ;;
"")
	case "$machine" in
	x86_64 | amd64) level=x86-64-v3 ;;
	*) exit 0 ;;
	esac
	;;
esac
echo "-microarch:$level"
