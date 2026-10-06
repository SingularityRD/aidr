import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from artifacts import sha256_file
from build_public_corpus import build, privy_spans


def row(text, value, kind, key):
    start = text.index(value)
    return {'full_text': text, 'masked': text[:start] + '{{' + key + '}}' + text[start + len(value):],
            'spans': [{'entity_type': kind, 'entity_value': value, 'start_position': start, 'end_position': start + len(value)}], 'template_id': 1}


class PublicCorpusTests(unittest.TestCase):
    def test_generic_location_is_not_an_address(self):
        self.assertIsNone(privy_spans(row('City: Ankara', 'Ankara', 'LOC', 'city')))
        actual = privy_spans(row('Address: 42 Main Road', '42 Main Road', 'LOC', 'address'))
        self.assertEqual(actual, [{'start': 9, 'end': 21, 'type': 'ADDRESS'}])

    def test_inconsistent_source_annotation_is_rejected(self):
        source = row('Name: Jane Doe', 'Jane Doe', 'PER', 'name')
        source['spans'][0]['start_position'] += 1
        self.assertIsNone(privy_spans(source))
        source = row('Name: Jane Doe', 'Jane Doe', 'PER', 'name')
        source['masked'] = 'Changed literal: {{name}}'
        self.assertIsNone(privy_spans(source))

    def test_other_sensitive_types_do_not_become_clean_negatives(self):
        self.assertIsNone(privy_spans(row('Password: abcdef', 'abcdef', 'PASSWORD', 'password')))
        self.assertEqual(privy_spans(row('Status: active', 'active', 'O', 'string')), [])

    def test_conversion_retains_source_spans_and_utf16_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            tr = [{'text': 'Ad: Ayşe', 'label': [{'category': 'private_person', 'start': 4, 'end': 8}]},
                  {'text': 'Adres: 42 Sokak', 'label': [{'category': 'private_address', 'start': 7, 'end': 15}]}]
            (source / 'btx-test.jsonl').write_text('\n'.join(map(json.dumps, tr)), encoding='utf-8')
            (source / 'tr_privacy_tr_curated.jsonl').write_text(json.dumps({'text': 'İşlem tamam.', 'spans': {}, 'info': {'id': 'clean'}}), encoding='utf-8')
            en = [row('😀 Jane Doe', 'Jane Doe', 'PER', 'name'), row('At 42 Main Road', '42 Main Road', 'LOC', 'street_address'), row('Status active', 'active', 'O', 'string')]
            with zipfile.ZipFile(source / 'privy-dataset.zip', 'w') as archive:
                archive.writestr('test-small.json', json.dumps(en))
            files = {p.name: {'size': p.stat().st_size, 'sha256': sha256_file(p)} for p in source.iterdir()}
            rows, provenance = build(source, {'datasets': [{'files': files}]}, 1)
            self.assertEqual(len(rows), 6)
            self.assertFalse(provenance['independentCorporate'])
            person = next(r for r in rows if r['language'] == 'en' and r['spans'] and r['spans'][0]['type'] == 'PERSON')
            self.assertEqual(person['spans'], [{'start': 3, 'end': 11, 'type': 'PERSON'}])
            self.assertTrue(all(r['origin'] == 'synthetic' for r in rows))


if __name__ == '__main__':
    unittest.main()
