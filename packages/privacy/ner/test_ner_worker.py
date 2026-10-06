"""Tokenizer restoration contract tests; no model-quality claim."""
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import ner_worker
from ner_worker import restore_tokenizer_normalizer

class TokenizerNormalizerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_restore(self, expected, backend):
        (self.root / 'tokenizer.json').write_text(json.dumps({'normalizer': expected}), encoding='utf-8')
        pinned = SimpleNamespace(normalizer=expected)
        module = SimpleNamespace(Tokenizer=SimpleNamespace(from_file=lambda path: pinned))
        with patch.dict(sys.modules, {'tokenizers': module}):
            restore_tokenizer_normalizer(SimpleNamespace(backend_tokenizer=backend), self.root)

    def test_verified_normalizer_restored_without_changing_other_fields(self):
        expected = {'type': 'Sequence', 'normalizers': [{'type': 'Strip', 'strip_left': True, 'strip_right': True}]}
        class Backend:
            normalizer = {'type': 'NFC'}
            def to_str(self):
                return json.dumps({'normalizer': self.normalizer, 'model': {'type': 'Unigram'}})
        backend = Backend()
        self.run_restore(expected, backend)
        self.assertEqual(json.loads(backend.to_str()), {'normalizer': expected, 'model': {'type': 'Unigram'}})

    def test_verified_null_normalizer_restored(self):
        class Backend:
            normalizer = {'type': 'NFC'}
            def to_str(self): return json.dumps({'normalizer': self.normalizer})
        backend = Backend()
        self.run_restore(None, backend)
        self.assertIsNone(backend.normalizer)

    def test_unrestored_normalizer_fails_closed(self):
        class Backend:
            def to_str(self): return json.dumps({'normalizer': {'type': 'NFC'}})
        with self.assertRaisesRegex(ValueError, 'TOKENIZER_NORMALIZER_MISMATCH'):
            self.run_restore({'type': 'NFKC'}, Backend())

    def test_non_json_tokenizer_uses_its_existing_loader(self):
        restore_tokenizer_normalizer(SimpleNamespace(), self.root)

class WorkerCheckpointTests(unittest.TestCase):
    def run_worker(self, loading):
        # Startup exercises the real guard before advertising ready; synthetic models are not inference evidence.
        with tempfile.TemporaryDirectory() as directory:
            model = SimpleNamespace(config=SimpleNamespace(model_type='bert', max_position_embeddings=512, id2label={0: 'O', 1: 'B-PER'}))
            model.to = lambda device: model
            model.eval = lambda: model
            tokenizer = SimpleNamespace(is_fast=True, model_max_length=512)
            transformers = SimpleNamespace(
                AutoTokenizer=SimpleNamespace(from_pretrained=lambda *args, **kwargs: tokenizer),
                AutoModelForTokenClassification=SimpleNamespace(from_pretrained=lambda *args, **kwargs: (model, loading)))
            logger = SimpleNamespace(set_verbosity_error=lambda: None, disable_progress_bar=lambda: None)
            torch = SimpleNamespace(set_num_threads=lambda count: None, set_num_interop_threads=lambda count: None)
            manifest = {'models': [{'_root': directory, 'languages': ['en'], 'label_map': {'O': None, 'PER': 'PERSON'}}]}
            output = io.StringIO()
            with patch.dict(sys.modules, {'torch': torch, 'transformers': transformers,
                                         'transformers.utils': SimpleNamespace(logging=logger)}), \
                 patch.object(ner_worker, 'verified_manifest', return_value=manifest), \
                 patch.object(sys, 'argv', ['ner_worker.py', '--manifest', directory, '--manifest-sha256', 'a' * 64]), \
                 patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO())), \
                 patch.object(sys, 'stdout', output):
                try:
                    result = ner_worker.main()
                except Exception:
                    self.assertEqual(output.getvalue(), '', 'Invalid checkpoint must never advertise ready')
                    raise
            return result, output.getvalue()

    def test_complete_checkpoint_advertises_ready(self):
        result, output = self.run_worker({key: [] for key in ('missing_keys', 'unexpected_keys', 'mismatched_keys', 'error_msgs')})
        self.assertEqual(result, 0)
        self.assertTrue(json.loads(output)['ready'])

    def test_incomplete_or_extra_checkpoint_never_advertises_ready(self):
        for key in ('missing_keys', 'unexpected_keys', 'mismatched_keys', 'error_msgs'):
            loading = {name: [] for name in ('missing_keys', 'unexpected_keys', 'mismatched_keys', 'error_msgs')}
            loading[key] = ['classifier.weight']
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'CHECKPOINT_LOAD_MISMATCH'):
                self.run_worker(loading)

    def test_missing_loading_contract_never_advertises_ready(self):
        with self.assertRaises(KeyError):
            self.run_worker({})

if __name__ == '__main__': unittest.main()
