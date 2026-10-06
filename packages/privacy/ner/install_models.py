#!/usr/bin/env python3
"""Connected staging installer for hash-pinned, unqualified public candidates.
The offline worker never calls this installer. An administrator reviews the lock,
licences and generated manifest before distributing its digest as a trust anchor.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path, PurePosixPath
from artifacts import ArtifactError, TYPES, sha256_file, verified_manifest


def safe_path(value: str) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_.\-/]+', value)) and not PurePosixPath(value).is_absolute() and all(p and p not in {'.', '..'} for p in value.split('/'))


def validate_lock(lock: dict) -> None:
    if lock.get('version') != 1 or not isinstance(lock.get('models'), list) or not 1 <= len(lock['models']) <= 4:
        raise ArtifactError('INVALID_INSTALL_LOCK')
    directories = set()
    for model in lock['models']:
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', model.get('repository', '')) or not re.fullmatch('[a-f0-9]{40}', model.get('revision', '')):
            raise ArtifactError('IMMUTABLE_REPOSITORY_REQUIRED')
        directory = model.get('directory')
        if not safe_path(directory) or directory in directories or not model.get('license'):
            raise ArtifactError('INVALID_INSTALL_LOCK')
        directories.add(directory)
        if not model.get('languages') or not set(model['languages']) <= {'tr', 'en'}:
            raise ArtifactError('INVALID_LANGUAGE')
        labels = model.get('label_map', {})
        if not labels or labels.get('O', 'missing') is not None or any(v is not None and v not in TYPES for v in labels.values()):
            raise ArtifactError('INVALID_LABEL_MAP')
        length, stride = model.get('max_length'), model.get('stride')
        if type(length) is not int or not 32 <= length <= 512 or type(stride) is not int or not 1 <= stride < length - 4:
            raise ArtifactError('INVALID_WINDOW')
        files = model.get('files', {})
        if not 4 <= len(files) <= 32 or not {'config.json', 'tokenizer.json', 'README.md'} <= set(files) or not any(f.endswith('.safetensors') for f in files):
            raise ArtifactError('INVALID_INVENTORY')
        for name, spec in files.items():
            if not safe_path(name) or '/' in name or Path(name).suffix not in {'.json', '.safetensors', '.txt', '.md', '.model'} or not safe_path(spec.get('source')):
                raise ArtifactError('UNSAFE_ARTIFACT_PATH')
            if not re.fullmatch('[a-f0-9]{64}', spec.get('sha256', '')) or type(spec.get('size')) is not int or not 0 < spec['size'] <= 2 * 1024 ** 3:
                raise ArtifactError('INVALID_INVENTORY')


class HttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith('https://'):
            raise ArtifactError('INSECURE_ARTIFACT_REDIRECT')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_file(url: str, path: Path, spec: dict) -> None:
    if path.exists():
        if path.is_symlink() or path.stat().st_size != spec['size'] or sha256_file(path) != spec['sha256']:
            raise ArtifactError('EXISTING_ARTIFACT_MISMATCH')
        return
    part = path.with_name(path.name + '.part')
    if part.exists():
        raise ArtifactError('PARTIAL_ARTIFACT_PRESENT')
    try:
        with part.open('xb') as output, urllib.request.build_opener(HttpsRedirect()).open(url, timeout=60) as response:
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > spec['size']:
                    raise ArtifactError('ARTIFACT_SIZE_MISMATCH')
                output.write(block)
        if total != spec['size'] or sha256_file(part) != spec['sha256']:
            raise ArtifactError('ARTIFACT_DIGEST_MISMATCH')
        part.replace(path)
    except Exception:
        if part.is_file() and not part.is_symlink():
            part.unlink()
        raise


def install(lock: dict, destination: Path, python: Path) -> dict:
    validate_lock(lock)
    if not python.is_file():
        raise ArtifactError('PYTHON_EXECUTABLE_REQUIRED')
    if any(p.is_symlink() for p in [destination, *destination.parents]):
        raise ArtifactError('UNSAFE_ARTIFACT_PATH')
    destination.mkdir(parents=True, exist_ok=True)
    models = []
    for source in lock['models']:
        root = destination / source['directory']
        if any(p.is_symlink() for p in [root, *root.parents]):
            raise ArtifactError('UNSAFE_ARTIFACT_PATH')
        root.mkdir(parents=True, exist_ok=True)
        for name, spec in source['files'].items():
            url = f"https://huggingface.co/{source['repository']}/resolve/{source['revision']}/{spec['source']}"
            download_file(url, root / name, spec)
        config = json.loads((root / 'config.json').read_text('utf-8'))
        if config.get('auto_map') or config.get('model_type') not in {'bert', 'distilbert', 'deberta-v2', 'xlm-roberta', 'roberta', 'modernbert'}:
            raise ArtifactError('UNSUPPORTED_MODEL_ARCHITECTURE')
        actual = {re.sub(r'^[BIESLU]-', '', label) for label in config['id2label'].values()}
        if actual != set(source['label_map']) or not {'PERSON', 'ADDRESS'} <= {source['label_map'][label] for label in actual}:
            raise ArtifactError('MODEL_LABEL_COVERAGE_MISMATCH')
        models.append({k: source[k] for k in ['directory', 'repository', 'revision', 'license', 'languages', 'max_length', 'stride', 'label_map']} | {'files': {name: spec['sha256'] for name, spec in source['files'].items()}})
    manifest = destination / 'manifest.json'
    encoded = json.dumps({'version': 1, 'approved': False, 'qualificationStatus': 'independent-corpus-required', 'models': models}, indent=2, ensure_ascii=False) + '\n'
    if manifest.exists() and manifest.read_text('utf-8') != encoded:
        raise ArtifactError('EXISTING_MANIFEST_MISMATCH')
    manifest.write_text(encoded, encoding='utf-8')
    digest = sha256_file(manifest)
    verified_manifest(manifest, digest)
    provider = {'command': str(python.resolve()), 'args': [str(Path(__file__).with_name('ner_worker.py').resolve()), '--manifest', str(manifest.resolve()), '--manifest-sha256', digest, '--threads', '2'], 'startupTimeoutMs': 120000, 'maxResponseBytes': 1048576}
    (destination / 'local-provider.json').write_text(json.dumps(provider, indent=2) + '\n', encoding='utf-8')
    return {'status': 'installed-unqualified-candidates', 'manifestSha256': digest, 'models': [{'repository': m['repository'], 'revision': m['revision'], 'license': m['license'], 'languages': m['languages']} for m in models]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, default=Path(__file__).with_name('public-models.lock.json'))
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--python', type=Path, default=Path(sys.executable))
    args = parser.parse_args()
    try:
        print(json.dumps(install(json.loads(args.lock.read_text('utf-8')), args.destination.absolute(), args.python), separators=(',', ':')))
    except Exception:
        sys.stderr.write('MODEL_INSTALL_FAILED\n')
        raise SystemExit(2)
