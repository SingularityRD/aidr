"""Decoder contract tests, not evidence of model inference quality."""
import itertools
import json
import tempfile
import unittest
from pathlib import Path
from bioes import BIAS_KEYS, decode_bioes, require_default_calibration

class BioesTests(unittest.TestCase):
    labels = ['O', 'B-PERSON', 'I-PERSON', 'E-PERSON', 'S-PERSON',
              'B-ADDRESS', 'I-ADDRESS', 'E-ADDRESS', 'S-ADDRESS']

    def test_valid_path_matches_exhaustive_optimum_with_invalid_local_argmax(self):
        emissions = [[-4, -1, 0, -3, -2, -7, -7, -7, -7],
                     [-4, -3, -1, -2, 0, -7, -7, -7, -7],
                     [-3, 0, -1, -2, -4, -7, -7, -7, -7]]
        def valid(path):
            states = [('O', '') if self.labels[i] == 'O' else (self.labels[i][0], self.labels[i][2:]) for i in path]
            return states[0][0] in 'OBS' and states[-1][0] in 'OES' and all(
                (p in 'OES' and n in 'OBS') or (p in 'BI' and n in 'IE' and a == b)
                for (p, a), (n, b) in zip(states, states[1:]))
        score = lambda path: sum(row[i] for row, i in zip(emissions, path))
        optimum = max(score(path) for path in itertools.product(range(len(self.labels)), repeat=3) if valid(path))
        decoded = decode_bioes(emissions, self.labels)
        self.assertTrue(valid(decoded))
        self.assertEqual(score(decoded), optimum)

    def test_entity_type_cannot_change_mid_span_and_singleton_is_preserved(self):
        emissions = [[-20] * 9 for _ in range(3)]
        emissions[0][1] = 0
        emissions[1][6] = 0
        emissions[1][2] = -1
        emissions[2][3] = 0
        self.assertEqual(decode_bioes(emissions, self.labels), [1, 2, 3])
        self.assertEqual(decode_bioes([[-9, -9, -9, -9, 0, -9, -9, -9, -9]], self.labels), [4])

    def test_invalid_labels_scores_and_incomplete_bioes_fail_closed(self):
        for labels in [['O', 'I-PERSON'], ['O', 'O'], ['O', 'PERSON'], ['O', 'B-', 'I-', 'E-', 'S-']]:
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                decode_bioes([], labels)
        for emissions in [[[0]], [[float('nan')] * 9], [[float('inf')] * 9]]:
            with self.subTest(emissions=emissions), self.assertRaises(ValueError):
                decode_bioes(emissions, self.labels)
        self.assertEqual(decode_bioes([], self.labels), [])

    def test_only_reviewed_zero_bias_default_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'viterbi_calibration.json'
            value = {'operating_points': {'default': {'biases': dict.fromkeys(BIAS_KEYS, 0.0)}}}
            path.write_text(json.dumps(value), encoding='utf-8')
            require_default_calibration(root)
            for modification in ['nonzero', 'missing', 'boolean', 'newpoint']:
                invalid = json.loads(json.dumps(value))
                if modification == 'nonzero': invalid['operating_points']['default']['biases'][next(iter(BIAS_KEYS))] = 1
                elif modification == 'missing': invalid['operating_points']['default']['biases'].pop(next(iter(BIAS_KEYS)))
                elif modification == 'boolean': invalid['operating_points']['default']['biases'][next(iter(BIAS_KEYS))] = False
                else: invalid['operating_points']['high-recall'] = invalid['operating_points']['default']
                path.write_text(json.dumps(invalid), encoding='utf-8')
                with self.subTest(modification=modification), self.assertRaises(ValueError): require_default_calibration(root)

if __name__ == '__main__': unittest.main()
