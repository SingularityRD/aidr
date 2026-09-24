"""Artifact and offset tests; fixture bytes are NOT loadable model weights.
No inference-quality claim is made by these tests.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from artifacts import ArtifactError, aggregate_tokens, sha256_file, utf16_offsets, verified_manifest

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
        config = self.root / 'configuration.json'
        config.write_text(json.dumps({'version': 1, 'models': [self.spec]}))
        completed = subprocess.run([sys.executable, str(Path(__file__).with_name('build_manifest.py')),
                                    '--config', str(config), '--output', str(self.path)],
                                   capture_output=True, text=True, timeout=10, check=True)
        digest = completed.stdout.strip()
        self.assertEqual(digest, sha256_file(self.path))
        self.assertEqual(verified_manifest(self.path, digest)['version'], 1)

    def test_sha256_empty_file(self):
        path = self.root / 'empty'
        path.write_bytes(b'')
        self.assertEqual(sha256_file(path), hashlib.sha256(b'').hexdigest())

class OffsetTests(unittest.TestCase):
    def test_ascii(self): self.assertEqual(utf16_offsets('Jane'), [0, 1, 2, 3, 4])
    def test_turkish(self): self.assertEqual(utf16_offsets('Çağrı'), [0, 1, 2, 3, 4, 5])
    def test_emoji(self): self.assertEqual(utf16_offsets('😀 A'), [0, 2, 3, 4])
    def test_combining(self): self.assertEqual(utf16_offsets('A\u0301'), [0, 1, 2])
    def test_empty(self): self.assertEqual(utf16_offsets(''), [0])
    def test_surrogates_rejected(self):
        for s in ['\ud800', '\udfff']:
            with self.subTest(s=repr(s)), self.assertRaises(ArtifactError): utf16_offsets(s)

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
