"""No OCR here: compare independently known synthetic glyph bounds with output pixels."""
from pathlib import Path
import json
from PIL import Image
root = Path(__file__).resolve().parents[2]
cases = [
 ('turkish-png.redacted.png','turkish'),
 ('english-dark-png.redacted.png','english-dark'),
 ('turkish-jpg.redacted.png','turkish'),
 ('turkish-oriented-jpg.redacted.png','turkish'),
 ('turkish-webp.redacted.png','turkish'),
]
records = []
for name, truth in cases:
    with Image.open(root/'reports/visual'/name) as im:
        assert im.mode == 'RGB' and not im.info, name
        boxes = json.loads((root/f'fixtures/visual/{truth}.truth.json').read_text('utf-8'))
        for entry in boxes:
            b = entry['box']
            crop = im.crop((b['x'],b['y'],b['x']+b['width'],b['y']+b['height']))
            assert crop.getextrema() == ((0,0),(0,0),(0,0)), (name, entry)
        records.append({'output':name,'sensitiveRows':len(boxes),'allSensitiveGlyphBoundsBlack':True,'opaqueRgb':True,'metadataEmpty':True})
report = {'cases':records,'totalSensitiveRows':sum(x['sensitiveRows'] for x in records)}
print(json.dumps(report,indent=2))
