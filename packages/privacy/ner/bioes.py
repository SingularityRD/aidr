"""Constrained BIOES decoding for the native OpenAI privacy-filter checkpoint.
The pinned author default has zero transition biases; other operating points need review.
Algorithm: github.com/openai/privacy-filter/blob/f7f00ca7fb869683eb732c010299d901457f19c3/opf/_core/decoding.py
"""
import json
import math
from pathlib import Path

BIAS_KEYS = frozenset('transition_bias_background_stay transition_bias_background_to_start '
    'transition_bias_end_to_background transition_bias_end_to_start '
    'transition_bias_inside_to_continue transition_bias_inside_to_end'.split())

def require_default_calibration(root: Path) -> None:
    value = json.loads((root / 'viterbi_calibration.json').read_text(encoding='utf-8'))
    if set(value) != {'operating_points'} or set(value['operating_points']) != {'default'}:
        raise ValueError('UNSUPPORTED_BIOES_CALIBRATION')
    point = value['operating_points']['default']
    if set(point) != {'biases'} or set(point['biases']) != BIAS_KEYS or any(
            type(v) not in (int, float) or v != 0 for v in point['biases'].values()):
        raise ValueError('UNSUPPORTED_BIOES_CALIBRATION')

def decode_bioes(emissions: list[list[float]], labels: list[str]) -> list[int]:
    """Maximum-probability valid path; no confidence filtering or label dropping."""
    states = [('O', '') if label == 'O' else (label[:1], label[2:]) for label in labels]
    if not labels or len(set(labels)) != len(labels) or labels.count('O') != 1 or any(
            label != 'O' and (len(label) < 3 or label[1] != '-' or state[0] not in 'BIES')
            for label, state in zip(labels, states)):
        raise ValueError('INVALID_BIOES_LABELS')
    for category in {category for _, category in states if category}:
        if {prefix for prefix, name in states if name == category} != set('BIES'):
            raise ValueError('INVALID_BIOES_LABELS')
    if any(len(row) != len(labels) or any(not math.isfinite(value) for value in row) for row in emissions):
        raise ValueError('INVALID_BIOES_EMISSIONS')
    if not emissions:
        return []
    incoming = [[i for i, (previous, old_category) in enumerate(states)
                 if (previous in 'OES' and current in 'OBS') or
                    (previous in 'BI' and current in 'IE' and old_category == category)]
                for current, category in states]
    scores = [value if prefix in 'OBS' else -math.inf for value, (prefix, _) in zip(emissions[0], states)]
    history = []
    for row in emissions[1:]:
        parents = [max(indices, key=scores.__getitem__) for indices in incoming]
        scores = [scores[parent] + value for parent, value in zip(parents, row)]
        history.append(parents)
    final = max((i for i, (prefix, _) in enumerate(states) if prefix in 'OES'), key=scores.__getitem__)
    result = [final]
    for parents in reversed(history):
        result.append(parents[result[-1]])
    return list(reversed(result))
