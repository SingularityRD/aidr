import test from 'node:test';
import assert from 'node:assert/strict';
import {VisualPrivacyEngine} from '../../dist/visual/engine.js';
import {LocalImageProcess} from '../../dist/visual/local-process.js';
import {backend,input,textEngine} from './helpers.mjs';

// Windows built-in OCR backend (vision/windows_ocr.ps1) and endpoints without a barcode decoder.
const windowsScan=(extra={})=>s=>({...s,languages:['tur'],ocrEngine:'windows',...extra});
const engine=(mutateScan,options={},lines)=>new VisualPrivacyEngine({backend:backend({mutateScan,...(lines?{lines}:{})}),textEngine:textEngine(),...options});

test('a Windows OCR scan needs only the Turkish recognizer; a Tesseract scan still needs eng+tur',async()=>{
  const ok=await engine(windowsScan(),{},['Email: jane@example.com']).inspect(input);
  assert.equal(ok.decision,'block');assert.deepEqual({...ok.counts},{EMAIL:1});
  const tesseract=await engine(s=>({...s,languages:['tur']})).inspect(input);
  assert.deepEqual([tesseract.decision,tesseract.reasons],['review',['IMAGE_OCR_UNAVAILABLE']]);
  const bogus=await engine(windowsScan({ocrEngine:'cloud'})).inspect(input);
  assert.deepEqual(bogus.reasons,['IMAGE_PROTOCOL_INVALID']);
});

test('no barcode decoder: clean text is review (never allow) unless the policy accepts the gap',async()=>{
  const lines=['Toplanti yarin saat onda'];
  const none=windowsScan({barcodeCoverage:'none'});
  const review=await engine(none,{},lines).inspect(input);
  assert.deepEqual([review.decision,review.reasons],['review',['IMAGE_BARCODE_NOT_CHECKED']]);
  const allow=await engine(none,{barcodeUnavailable:'allow'},lines).inspect(input);
  assert.equal(allow.decision,'allow');
  // Sensitive text is blocked either way.
  const sensitive=await engine(none,{},['Email: jane@example.com']).inspect(input);
  assert.equal(sensitive.decision,'block');
  // With a decoder (no barcodeCoverage), clean text is allowed as before.
  assert.equal((await engine(windowsScan(),{},lines).inspect(input)).decision,'allow');
  assert.deepEqual((await engine(windowsScan({barcodeCoverage:'partial'}),{},lines).inspect(input)).reasons,['IMAGE_PROTOCOL_INVALID']);
  assert.throws(()=>engine(none,{barcodeUnavailable:'maybe'}),/IMAGE_CONFIGURATION_INVALID/);
});

test('no barcode decoder: protect never releases bytes (residual barcode check impossible)',async()=>{
  const r=await engine(windowsScan({barcodeCoverage:'none'}),{release:'automatic'},['Email: jane@example.com']).protect(input);
  assert.equal(r.output,null);assert.deepEqual([r.decision,r.reasons],['block',['IMAGE_BARCODE_UNAVAILABLE']]);
});

test('LocalImageProcess: the Windows engine needs absolute powershell/script paths, Tesseract its own',()=>{
  const base={python:'C:\\v\\python.exe',manifest:'C:\\i\\ocr-manifest.json'};
  assert.doesNotThrow(()=>new LocalImageProcess({...base,ocrEngine:'windows',powershell:'C:\\W\\powershell.exe'}));
  assert.throws(()=>new LocalImageProcess({...base,ocrEngine:'windows'}),/IMAGE_CONFIGURATION_INVALID/);
  assert.throws(()=>new LocalImageProcess({...base,ocrEngine:'windows',powershell:'powershell.exe'}),/IMAGE_CONFIGURATION_INVALID/);
  assert.throws(()=>new LocalImageProcess({...base,ocrEngine:'easyocr',powershell:'C:\\W\\powershell.exe'}),/IMAGE_CONFIGURATION_INVALID/);
  assert.throws(()=>new LocalImageProcess(base),/IMAGE_CONFIGURATION_INVALID/);
});
