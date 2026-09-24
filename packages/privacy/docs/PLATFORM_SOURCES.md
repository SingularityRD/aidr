# Resmi teknik başvuru kaynakları

Erişim: 24 Eylül 2026. Bunlar tasarım başvuru kaynaklarıdır; bu kodun sertifikalandırıldığı anlamına gelmez. Tam Gartner/SANS değerlendirmesi önceki 0.4 araştırma belgesindedir; bu sürüm için ücretli yeni rapor veya üçüncü taraf penetrasyon testi alınmadı.

- OpenID Connect Core 1.0, errata 2: `https://openid.net/specs/openid-connect-core-1_0.html`
- Chrome ExtensionSettings, force_installed / update_url: `https://support.google.com/chrome/a/answer/9867568?hl=en`
- Chrome developer-mode policy: `https://chromeenterprise.google/policies/extension-developer-mode-settings/`
- SQLite WAL-reset bug and patched releases: `https://www.sqlite.org/wal.html` and `https://sqlite.org/releaselog/3_51_3.html`. The Node 22.16.0 test runtime embeds SQLite 3.49.1; this implementation defaults to DELETE journal instead of its affected WAL mode. That choice does not certify every other dependency/version safe.
- OWASP File Upload Cheat Sheet: `https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html`
- Safetensors format source/specification: `https://github.com/huggingface/safetensors`
- scikit-learn LogisticRegression: `https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html`. Actual training version here is 1.8.0; live documentation may describe newer versions.
- OpenAI Responses text and image input: `https://developers.openai.com/api/docs/guides/text` and `https://developers.openai.com/api/docs/guides/images-vision`
- Gemini generateContent: `https://ai.google.dev/api/generate-content`

Provider builders were based on the official request formats, but no authenticated provider request was sent. Exact permitted model IDs and API feature compatibility must be approved in the deployment.
