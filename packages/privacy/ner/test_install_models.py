"""Installer integrity tests; fixture bytes are not loadable model weights."""
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from artifacts import ArtifactError
from install_models import download_file, install, validate_lock


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lock = json.loads(Path(__file__).with_name('public-models.lock.json').read_text('utf-8'))

    def test_rejects_mutable_revisions_traversal_formats_and_windows_before_download(self):
        for key, value in [('revision', 'main'), ('directory', '../escape'), ('languages', ['xx']), ('stride', 0), ('license', '')]:
            lock = copy.deepcopy(self.lock)
            lock['models'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ArtifactError):
                validate_lock(lock)
        lock = copy.deepcopy(self.lock)
        lock['models'][0]['files']['unsafe.py'] = lock['models'][0]['files']['config.json']
        with self.assertRaises(ArtifactError):
            validate_lock(lock)

    def test_download_verifies_size_hash_and_preserves_existing_artifacts(self):
        data = b'fixture'
        spec = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        path = self.root / 'file.json'
        with patch('urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = io.BytesIO(data)
            download_file('https://huggingface.co/fixture', path, spec)
            self.assertEqual(path.read_bytes(), data)
            download_file('https://huggingface.co/fixture', path, spec)
            self.assertEqual(opener.return_value.open.call_count, 1)
        path.write_bytes(b'tamper')
        with self.assertRaisesRegex(ArtifactError, 'EXISTING_ARTIFACT_MISMATCH'):
            download_file('https://huggingface.co/fixture', path, spec)
        self.assertEqual(path.read_bytes(), b'tamper')

    def test_invalid_profile_rejected_before_executable_or_download(self):
        self.lock['models'][0]['aggregation'] = 'first'
        with patch('install_models.download_file') as download, self.assertRaisesRegex(ArtifactError, 'INVALID_AGGREGATION'):
            install(self.lock, self.root / 'not-created', self.root / 'no-python')
        download.assert_not_called()
        self.assertFalse((self.root / 'not-created').exists())

    def test_large_native_safetensors_stays_bounded_without_allowing_large_config(self):
        lock = copy.deepcopy(self.lock)
        lock['models'][0]['files']['model.safetensors']['size'] = 2798989498
        validate_lock(lock)
        for name, size in [('model.safetensors', 4 * 1024 ** 3 + 1), ('config.json', 2 * 1024 ** 3 + 1)]:
            invalid = copy.deepcopy(lock)
            invalid['models'][0]['files'][name]['size'] = size
            with self.subTest(name=name), self.assertRaisesRegex(ArtifactError, 'INVALID_INVENTORY'):
                validate_lock(invalid)

    def test_bad_download_never_publishes_a_model_file(self):
        for size, digest in [(8, hashlib.sha256(b'fixture').hexdigest()), (7, '0' * 64), (1, '0' * 64)]:
            with self.subTest(size=size), patch('urllib.request.build_opener') as opener:
                opener.return_value.open.return_value = io.BytesIO(b'fixture')
                path = self.root / 'model.safetensors'
                with self.assertRaises(ArtifactError):
                    download_file('https://huggingface.co/fixture', path, {'size': size, 'sha256': digest})
                self.assertFalse(path.exists())
                self.assertFalse(path.with_suffix('.safetensors.part').exists())

    def test_install_inspects_actual_labels_and_generates_digest_pinned_provider(self):
        model = self.lock['models'][1]
        model['aggregation'] = 'first_word'
        self.lock['models'] = [model]
        content = {'config.json': json.dumps({'model_type': 'distilbert', 'id2label': {'0': 'O', '1': 'B-PERSON_NAME', '2': 'B-ADDRESS'}}).encode(),
                   'tokenizer.json': b'{}', 'tokenizer_config.json': b'{}', 'model.safetensors': b'NOT_REAL_WEIGHTS', 'README.md': b'fixture'}
        model['label_map'] = {'O': None, 'PERSON_NAME': 'PERSON', 'ADDRESS': 'ADDRESS'}
        model['files'] = {name: {'source': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in content.items()}
        def fixture_download(url, path, spec):
            path.write_bytes(content[path.name])
        with patch('install_models.download_file', fixture_download):
            result = install(self.lock, self.root / 'installed', Path(sys.executable))
        provider = json.loads((self.root / 'installed/local-provider.json').read_text())
        self.assertEqual(provider['args'][provider['args'].index('--manifest-sha256') + 1], result['manifestSha256'])
        self.assertEqual(result['status'], 'installed-unqualified-candidates')
        manifest = json.loads((self.root / 'installed/manifest.json').read_text())
        self.assertIs(manifest['approved'], False)
        self.assertEqual(manifest['qualificationStatus'], 'independent-corpus-required')
        self.assertEqual(manifest['models'][0]['aggregation'], 'first_word')
        content['config.json'] = json.dumps({'model_type': 'distilbert', 'id2label': {'0': 'O', '1': 'B-PERSON_NAME', '2': 'B-LOC'}}).encode()
        with patch('install_models.download_file', fixture_download), self.assertRaisesRegex(ArtifactError, 'MODEL_LABEL_COVERAGE_MISMATCH'):
            install(self.lock, self.root / 'wrong-labels', Path(sys.executable))

    def test_symlink_destination_rejected(self):
        target = self.root / 'target'
        target.mkdir()
        link = self.root / 'linked'
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ArtifactError, 'UNSAFE_ARTIFACT_PATH'):
            install(self.lock, link, Path(sys.executable))


if __name__ == '__main__':
    unittest.main()
