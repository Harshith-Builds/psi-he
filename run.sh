#!/usr/bin/env bash
# Reproduces every number and figure in the evaluation report.
#
#   ./run.sh            build, unit tests, demo, full benchmarks (|S| = 2^20 for sets A and B), figures
#   ./run.sh --quick    same, but 1 trial and |S| = 2^16 for every set (about 2 minutes)
#   ./run.sh --no-build skip the CMake build (used inside the Docker image, which is already built)
#
# Output goes to results/: tests.txt, demo.txt, A.json, B.json, C.json, bench.log, fig_*.png, summary.md
set -euo pipefail
cd "$(dirname "$0")"

QUICK=0
BUILD=1
for a in "$@"; do
  case "$a" in
    --quick) QUICK=1 ;;
    --no-build) BUILD=0 ;;
    *) echo "unknown option $a"; exit 2 ;;
  esac
done

if [[ $BUILD -eq 1 ]]; then
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
  cmake --build build -j"$(nproc)"
fi
mkdir -p results

echo "== unit and end-to-end tests"
if [[ $QUICK -eq 1 ]]; then ./build/psi_tests --quick | tee results/tests.txt
else ./build/psi_tests | tee results/tests.txt; fi

echo "== demo"
./build/psi_demo | tee results/demo.txt

echo "== benchmarks"
: > results/bench.log
for s in A B C; do
  if [[ $QUICK -eq 1 ]]; then
    ./build/psi_bench --set "$s" --trials 1 --server 65536 --out "results/$s.json" 2>&1 | tee -a results/bench.log
  else
    ./build/psi_bench --set "$s" --trials 5 --out "results/$s.json" 2>&1 | tee -a results/bench.log
  fi
done

echo "== figures and summary table"
python3 scripts/make_figures.py results
echo "done: see results/summary.md"
