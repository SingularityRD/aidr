# Primary implementation references

References consulted for this extension (24 September 2026). These describe upstream capabilities; they are not evidence of this module's performance.

- Tesseract CLI, language combinations, TSV boxes and segmentation: https://tesseract-ocr.github.io/tessdoc/Command-Line-Usage.html
- Tesseract image quality, skew, resolution and preprocessing limitations: https://tesseract-ocr.github.io/tessdoc/ImproveQuality.html
- Pillow Image API, decoding and decompression-bomb limits: https://pillow.readthedocs.io/en/stable/reference/Image.html
- Pillow EXIF transpose: https://pillow.readthedocs.io/en/stable/reference/ImageOps.html
- Pillow license: https://github.com/python-pillow/Pillow/blob/main/LICENSE
- Tesseract license: https://github.com/tesseract-ocr/tesseract/blob/main/LICENSE
- pyzbar bindings, bounding rectangles and license/dependency notice: https://github.com/NaturalHistoryMuseum/pyzbar
- zbar supported barcode families and native implementation: https://github.com/mchehab/zbar
- Presidio image-redaction architecture (reviewed, not copied/bundled): https://github.com/microsoft/presidio/tree/main/presidio-image-redactor

Implementation choice: keep the delivered TypeScript PII/policy motor, add a local Python/native OCR boundary rather than duplicate the text detector or send screenshots to an external vision API. pyzbar/libzbar was actually available and tested; ZXing/PaddleOCR are not deployed in this release. No comparative SOTA accuracy or throughput result was obtained.
