"""Artifact and offset tests; fixture bytes are NOT loadable model weights.
No inference-quality claim is made by these tests.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from artifacts import ArtifactError, aggregate_tokens, encode_first_words, sha256_file, utf16_offsets, verified_manifest

class ArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.model = self.root / 'model'
        self.model.mkdir()
        for name, data in [('config.json', b'{}'), ('tokenizer.json', b'{}'), ('model.safetensors', b'NOT_REAL_WEIGHTS')]:
            (self.model / name).write_bytes(data)
        self.spec = {'directory': 'model', 'languages': ['tr', 'en'],
                     'label_map': {'O': None, 'PER': 'PERSON', 'ADDR': 'ADDRESS'},
                     'max_length': 384, 'stride': 96}
        self.path = self.root / 'manifest.json'

    def write_manifest(self):
        self.spec['files'] = {p.relative_to(self.model).as_posix(): sha256_file(p)
                              for p in self.model.rglob('*') if p.is_file()}
        self.path.write_text(json.dumps({'version': 1, 'models': [self.spec]}))
        return sha256_file(self.path)

    def test_valid_inventory(self):
        digest = self.write_manifest()
        result = verified_manifest(self.path, digest)
        self.assertEqual(result['models'][0]['_root'], str(self.model))

    def test_wrong_manifest_digest(self):
        self.write_manifest()
        with self.assertRaises(ArtifactError): verified_manifest(self.path, '0' * 64)

    def test_invalid_digest_encoding(self):
        self.write_manifest()
        for digest in ['', 'abc', 'G' * 64, 'a' * 63]:
            with self.subTest(digest=digest), self.assertRaises(ArtifactError):
                verified_manifest(self.path, digest)

    def test_tampered_weight(self):
        digest = self.write_manifest()
        (self.model / 'model.safetensors').write_bytes(b'TAMPERED')
        with self.assertRaisesRegex(ArtifactError, 'ARTIFACT_DIGEST_MISMATCH'):
            verified_manifest(self.path, digest)

    def test_unlisted_file(self):
        digest = self.write_manifest()
        (self.model / 'extra.json').write_text('{}')
        with self.assertRaisesRegex(ArtifactError, 'INVENTORY_MISMATCH'):
            verified_manifest(self.path, digest)

    def test_missing_inventory_member(self):
        digest = self.write_manifest()
        (self.model / 'tokenizer.json').unlink()
        with self.assertRaisesRegex(ArtifactError, 'INVENTORY_MISMATCH'):
            verified_manifest(self.path, digest)

    def test_no_weights(self):
        (self.model / 'model.safetensors').unlink()
        digest = self.write_manifest()
        with self.assertRaisesRegex(ArtifactError, 'MODEL_WEIGHTS_MISSING'):
            verified_manifest(self.path, digest)

    def test_no_config(self):
        (self.model / 'config.json').unlink()
        digest = self.write_manifest()
        with self.assertRaisesRegex(ArtifactError, 'MODEL_WEIGHTS_MISSING'):
            verified_manifest(self.path, digest)

    def test_no_tokenizer(self):
        (self.model / 'tokenizer.json').unlink()
        digest = self.write_manifest()
        with self.assertRaisesRegex(ArtifactError, 'TOKENIZER_MISSING'):
            verified_manifest(self.path, digest)

    def test_unsafe_serialization_formats(self):
        for ext in ['.bin', '.pt', '.pth', '.pickle', '.pkl', '.py', '.pyc']:
            with self.subTest(ext=ext):
                bad = self.model / ('unsafe' + ext)
                bad.write_bytes(b'never executed')
                digest = self.write_manifest()
                with self.assertRaisesRegex(ArtifactError, 'UNSAFE_ARTIFACT_FORMAT'):
                    verified_manifest(self.path, digest)
                bad.unlink()

    def test_symlink_member(self):
        (self.model / 'alias.json').symlink_to(self.model / 'config.json')
        digest = self.write_manifest()
        with self.assertRaisesRegex(ArtifactError, 'SYMLINK_ARTIFACT'):
            verified_manifest(self.path, digest)

    def test_symlink_manifest(self):
        digest = self.write_manifest()
        link = self.root / 'alias-manifest.json'
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ArtifactError, 'INVALID_MANIFEST'):
            verified_manifest(link, digest)

    def test_symlink_model_directory(self):
        (self.root / 'alias').symlink_to(self.model, target_is_directory=True)
        self.spec['directory'] = 'alias'
        digest = self.write_manifest()
        with self.assertRaisesRegex(ArtifactError, 'UNSAFE_ARTIFACT_PATH'):
            verified_manifest(self.path, digest)

    def test_directory_traversal(self):
        for directory in ['../model', '/tmp/other-model']:
            with self.subTest(directory=directory):
                self.spec['directory'] = directory
                digest = self.write_manifest()
                with self.assertRaisesRegex(ArtifactError, 'UNSAFE_ARTIFACT_PATH'):
                    verified_manifest(self.path, digest)

    def test_wrong_language(self):
        self.spec['languages'] = ['xx']
        digest = self.write_manifest()
        with self.assertRaisesRegex(ArtifactError, 'INVALID_LANGUAGE'):
            verified_manifest(self.path, digest)

    def test_invalid_aggregation_profile_rejected(self):
        for aggregation in ['first', 'average', None, False, {}, []]:
            with self.subTest(aggregation=aggregation):
                self.spec['aggregation'] = aggregation
                digest = self.write_manifest()
                with self.assertRaisesRegex(ArtifactError, 'INVALID_AGGREGATION'):
                    verified_manifest(self.path, digest)

    def test_explicit_profile_preserved_without_changing_default(self):
        digest = self.write_manifest()
        self.assertNotIn('aggregation', verified_manifest(self.path, digest)['models'][0])
        self.spec['aggregation'] = 'first_word'
        digest = self.write_manifest()
        self.assertEqual(verified_manifest(self.path, digest)['models'][0]['aggregation'], 'first_word')

    def test_unknown_entity(self):
        self.spec['label_map']['PER'] = 'SECRET_CUSTOM_TYPE'
        digest = self.write_manifest()
        with self.assertRaisesRegex(ArtifactError, 'INVALID_LABEL_MAP'):
            verified_manifest(self.path, digest)

    def test_invalid_window(self):
        for max_length, stride in [(16, 8), (1024, 96), (384, 0), (384, 383), (384, -1), (384, 1.5)]:
            with self.subTest(window=(max_length, stride)):
                self.spec.update(max_length=max_length, stride=stride)
                digest = self.write_manifest()
                with self.assertRaisesRegex(ArtifactError, 'INVALID_WINDOW'):
                    verified_manifest(self.path, digest)

    def test_version_and_model_count(self):
        self.write_manifest()
        for obj in [{'version': 2, 'models': [self.spec]}, {'version': 1, 'models': []},
                    {'version': 1, 'models': [self.spec] * 5}]:
            with self.subTest(obj=obj):
                self.path.write_text(json.dumps(obj))
                with self.assertRaises(ArtifactError):
                    verified_manifest(self.path, sha256_file(self.path))

    def test_manifest_builder_cli(self):
        import subprocess
        import sys
        self.spec['aggregation'] = 'first_word'
        config = self.root / 'configuration.json'
        config.write_text(json.dumps({'version': 1, 'models': [self.spec]}))
        completed = subprocess.run([sys.executable, str(Path(__file__).with_name('build_manifest.py')),
                                    '--config', str(config), '--output', str(self.path)],
                                   capture_output=True, text=True, timeout=10, check=True)
        digest = completed.stdout.strip()
        self.assertEqual(digest, sha256_file(self.path))
        self.assertEqual(verified_manifest(self.path, digest)['version'], 1)
        self.assertEqual(verified_manifest(self.path, digest)['models'][0]['aggregation'], 'first_word')

    def test_sha256_empty_file(self):
        path = self.root / 'empty'
        path.write_bytes(b'')
        self.assertEqual(sha256_file(path), hashlib.sha256(b'').hexdigest())

    def test_manifest_builder_invalid_profile_never_publishes_output(self):
        import subprocess
        import sys
        self.spec['aggregation'] = 'average'
        config = self.root / 'invalid-config.json'
        config.write_text(json.dumps({'version': 1, 'models': [self.spec]}))
        completed = subprocess.run([sys.executable, str(Path(__file__).with_name('build_manifest.py')),
                                    '--config', str(config), '--output', str(self.path)],
                                   capture_output=True, text=True, timeout=10)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(self.path.exists())

class OffsetTests(unittest.TestCase):
    def test_ascii(self): self.assertEqual(utf16_offsets('Jane'), [0, 1, 2, 3, 4])
    def test_turkish(self): self.assertEqual(utf16_offsets('Çağrı'), [0, 1, 2, 3, 4, 5])
    def test_emoji(self): self.assertEqual(utf16_offsets('😀 A'), [0, 2, 3, 4])
    def test_combining(self): self.assertEqual(utf16_offsets('A\u0301'), [0, 1, 2])
    def test_empty(self): self.assertEqual(utf16_offsets(''), [0])
    def test_surrogates_rejected(self):
        for s in ['\ud800', '\udfff']:
            with self.subTest(s=repr(s)), self.assertRaises(ArtifactError): utf16_offsets(s)

class FirstWordTests(unittest.TestCase):
    text = "😀 Yılmaz'a\tAli"

    def tokenizer(self, overlap=2):
        class Encoding(dict):
            def word_ids(self, i=0): return self.words[i]
        full = Encoding(input_ids=[101, 10, 11, 12, 13, 14, 102],
                        offset_mapping=[(0, 0), (0, 1), (0, 6), (6, 7), (7, 8), (0, 3), (0, 0)],
                        special_tokens_mask=[1, 0, 0, 0, 0, 0, 1])
        full.words = [[None, 0, 1, 1, 1, 2, None]]
        start = 4 - overlap
        windows = Encoding(input_ids=[], offset_mapping=[], special_tokens_mask=[])
        windows.words = []
        for left, right in [(0, 4), (start, 5)]:
            windows['input_ids'].append([101] + full['input_ids'][1 + left:1 + right] + [102])
            windows['offset_mapping'].append([(0, 0)] + full['offset_mapping'][1 + left:1 + right] + [(0, 0)])
            windows['special_tokens_mask'].append([1] + [0] * (right - left) + [1])
            windows.words.append([None] + full.words[0][1 + left:1 + right] + [None])
        def tokenizer(values, **options):
            self.assertEqual(values, ['😀', "Yılmaz'a", 'Ali'])
            self.assertTrue(options['is_split_into_words'])
            return windows if options.get('return_overflowing_tokens') else full
        return tokenizer, full, windows

    def test_midword_overflow_never_promotes_unsupervised_continuation(self):
        tokenizer, _, _ = self.tokenizer()
        _, absolute, projected = encode_first_words(tokenizer, self.text, 6, 2)
        self.assertEqual(absolute[1][1], (8, 9))  # apostrophe at the second window's start
        self.assertEqual(projected[0], [None, (0, 1), (2, 10), None, None, None])
        self.assertEqual(projected[1], [None, None, None, (11, 14), None])
        self.assertEqual(utf16_offsets(self.text)[projected[0][2][1]], 11)

    def test_supervised_low_score_retained_and_continuation_logits_unused(self):
        tokenizer, _, _ = self.tokenizer()
        _, _, projected = encode_first_words(tokenizer, self.text, 6, 2)
        labels = ['O', 'O', 'B-PER', 'B-EMAIL', 'B-EMAIL', 'O']
        scores = [.9, .9, .01, .999, .999, .9]
        selected = [j for j, offset in enumerate(projected[0]) if offset is not None]
        result = aggregate_tokens(self.text, [projected[0][j] for j in selected],
            [labels[j] for j in selected], [scores[j] for j in selected], {'O': None, 'PER': 'PERSON', 'EMAIL': 'EMAIL'})
        self.assertEqual(result, [{'start': 2, 'end': 10, 'type': 'PERSON', 'score': .01}])

    def test_overlapping_true_first_piece_remains_eligible(self):
        tokenizer, _, _ = self.tokenizer(overlap=3)
        _, _, projected = encode_first_words(tokenizer, self.text, 6, 3)
        self.assertEqual(projected[1][1], (2, 10))
        self.assertEqual(projected[1][4], (11, 14))

    def test_alignment_gap_fails_closed(self):
        tokenizer, _, windows = self.tokenizer()
        windows['input_ids'][1][1] = 999
        with self.assertRaisesRegex(ArtifactError, 'INVALID_WORD_ALIGNMENT'):
            encode_first_words(tokenizer, self.text, 6, 2)

    def test_missing_original_word_fails_closed(self):
        tokenizer, full, _ = self.tokenizer()
        full.words[0][5] = 1
        with self.assertRaisesRegex(ArtifactError, 'INCOMPLETE_WORD_COVERAGE'):
            encode_first_words(tokenizer, self.text, 6, 2)

class AggregationTests(unittest.TestCase):
    mapping = {'O': None, 'PER': 'PERSON', 'ADDR': 'ADDRESS'}
    def run_aggregate(self, offsets, labels, scores=None, text='Jane Doe lives here'):
        return aggregate_tokens(text, offsets, labels, scores or [.9] * len(labels), self.mapping)

    def test_bio_joins_adjacent_words(self):
        result = self.run_aggregate([(0, 4), (5, 8)], ['B-PER', 'I-PER'])
        self.assertEqual(result, [{'start': 0, 'end': 8, 'type': 'PERSON', 'score': .9}])

    def test_low_confidence_not_dropped(self):
        result = self.run_aggregate([(0, 4), (5, 8)], ['B-PER', 'I-PER'], [.99, .01])
        self.assertEqual(result[0]['score'], .01)
        self.assertEqual(result[0]['end'], 8)

    def test_outer_whitespace_trim_preserves_content_internal_spaces_and_score(self):
        result = self.run_aggregate([(0, 6), (6, 12)], ['B-PER', 'I-PER'], [.99, .01], text=' \tJane Doe \n')
        self.assertEqual(result, [{'start': 2, 'end': 10, 'type': 'PERSON', 'score': .01}])
        text = ' \t42 Main Road.\n '
        result = self.run_aggregate([(0, len(text))], ['B-ADDR'], text=text)
        self.assertEqual(text[result[0]['start']:result[0]['end']], '42 Main Road.')

    def test_whitespace_begin_and_outside_tokens_still_split(self):
        for labels in [['B-PER', 'B-PER', 'I-PER'], ['B-PER', 'O', 'I-PER']]:
            with self.subTest(labels=labels):
                result = self.run_aggregate([(0, 4), (4, 6), (6, 9)], labels, text='Jane  Doe')
                self.assertEqual([(span['start'], span['end']) for span in result], [(0, 4), (6, 9)])

    def test_non_whitespace_unicode_and_other_type_content_not_trimmed(self):
        text = ' \u200bJo\u0301. '
        result = self.run_aggregate([(0, len(text))], ['B-PER'], text=text)
        self.assertEqual(text[result[0]['start']:result[0]['end']], '\u200bJo\u0301.')
        for kind in ['SECRET', 'PRIVATE_KEY', 'INTERNAL']:
            text = ' sensitive content \n'
            result = aggregate_tokens(text, [(0, len(text))], ['B-' + kind], [.01], {'O': None, kind: kind})
            self.assertEqual(result, [{'start': 0, 'end': len(text), 'type': kind, 'score': .01}])

    def test_begin_splits_entities(self):
        self.assertEqual(len(self.run_aggregate([(0, 4), (5, 8)], ['B-PER', 'B-PER'])), 2)

    def test_splits_across_o(self):
        result = self.run_aggregate([(0, 4), (5, 8), (9, 14)], ['B-PER', 'O', 'I-PER'])
        self.assertEqual(len(result), 2)

    def test_non_whitespace_gap_not_joined(self):
        self.assertEqual(len(self.run_aggregate([(0, 4), (15, 19)], ['B-PER', 'I-PER'])), 2)

    def test_special_offsets_ignored(self):
        result = self.run_aggregate([(0, 0), (0, 4), (0, 0)], ['O', 'B-PER', 'O'])
        self.assertEqual(len(result), 1)

    def test_single_and_end_labels(self):
        for labels in [['S-PER', 'I-PER'], ['U-PER', 'I-PER'], ['E-PER', 'I-PER'], ['L-PER', 'I-PER']]:
            with self.subTest(labels=labels):
                self.assertEqual(len(self.run_aggregate([(0, 4), (5, 8)], labels)), 2)

    def test_mixed_types_separate(self):
        self.assertEqual(len(self.run_aggregate([(0, 4), (5, 8)], ['B-PER', 'I-ADDR'])), 2)

    def test_unknown_label_blocks(self):
        with self.assertRaisesRegex(ArtifactError, 'UNMAPPED_LABEL'):
            self.run_aggregate([(0, 4)], ['B-OTHER'])

    def test_bad_scores(self):
        for score in [float('nan'), float('inf'), -0.01, 1.1]:
            with self.subTest(score=score), self.assertRaises(ArtifactError):
                self.run_aggregate([(0, 4)], ['B-PER'], [score])

    def test_bad_offsets(self):
        for offsets in [[(-1, 4)], [(4, 1)], [(0, 100)], [(1, 1)]]:
            with self.subTest(offsets=offsets), self.assertRaises(ArtifactError):
                self.run_aggregate(offsets, ['B-PER'])

    def test_length_mismatch(self):
        with self.assertRaises(ArtifactError):
            aggregate_tokens('Jane', [(0, 4)], ['B-PER'], [], self.mapping)

if __name__ == '__main__': unittest.main()
