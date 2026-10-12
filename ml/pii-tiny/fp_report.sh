#!/bin/bash
# Benign false-positive rate split by whether the prompt contains a distractor-pool term.
#   ./fp_report.sh <model-dir> [min-conf]
set -e
M=$1; T=${2:-0}; PY=${PY:-/home/user/.venvs/pii/bin/python}
for part in seen unseen; do
  $PY train_b.py --predict out/eval-benign-$part.jsonl --model "$M" --pred out/pred-benign-$part.jsonl --min-conf "$T"
  echo "$part: $(python3 eval.py --gold out/eval-benign-$part.jsonl --pred out/pred-benign-$part.jsonl | grep '^benign')"
done
