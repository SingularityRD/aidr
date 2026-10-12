# PII template specification

Templates are realistic prompts a person would paste into an AI chat (ChatGPT, Claude, Gemini,
Copilot) at work, with the free-text personal data replaced by **slots**. `gen.py` fills every
slot from large value pools, inflects Turkish suffixes, and records exact character spans, so a
template becomes many perfectly labelled training sentences.

The model only learns the entities rules cannot catch: **PERSON, ADDRESS, LOCATION**.
E-mails, phones, TCKN, IBAN, cards, secrets are already handled by checksum/pattern rules — but
templates SHOULD contain them as literal synthetic values (they are context, labelled `O`), e.g.
`ayse.k@example.com`, `0532 111 22 33`, so the model learns not to depend on their absence.

## File format

One JSON object per line (`.jsonl`), UTF-8:

```json
{"lang":"tr","domain":"customer-support","text":"Müşterimiz {PERSON1} dün aradı, {PERSON1.first+GEN} siparişi hâlâ {LOCATION1.city+ABL} çıkmamış."}
```

- `lang`: `tr`, `en` or `mix` (code-switched Turkish/English, very common in Turkish offices).
- `domain`: short tag (see the list in your assignment).
- `text`: the prompt. Use `\n` for line breaks. Length: 1 sentence up to ~12 lines.

## Slot grammar

`{TYPE<n>[.form][+SUFFIX]}` — `n` is a coreference index inside one template (`PERSON1`,
`PERSON2`...): the same `n` always refers to the same individual.

| TYPE | forms | notes |
|---|---|---|
| `PERSON` | `full` (default: first + last), `first`, `last`, `upper` (AHMET YILMAZ), `lower` (ahmet yılmaz), `initial` (A. Yılmaz), `firstlast2` (two given names: Ayşe Nur Demir) | Titles/honorifics stay OUTSIDE the slot: `Sayın {PERSON1}`, `{PERSON1.first} Hanım`, `{PERSON1.first} Bey`, `Dr. {PERSON1.last}`, `Mr. {PERSON1.last}`. |
| `ADDRESS` | `tr` (full TR address: mahalle, cadde/sokak, no, daire, ilçe/il), `tr_street` (street + number only), `en` (US/UK street address), `en_street` | Street-level, one span. |
| `LOCATION` | `city`, `district` (TR ilçe), `neighborhood` (TR mahalle), `country` | Use only where the place identifies/locates the person (where they live, were born, are travelling). |

Turkish suffix after the slot (Turkish texts only): `+GEN` ('ın / 'nin), `+DAT` ('a / 'ye),
`+ACC` ('ı / 'yi), `+LOC` ('da / 'te), `+ABL` ('dan / 'ten), `+INS` ('la / 'yle), `+PLU`
('lar). The generator writes the apostrophe and the vowel-harmonised suffix — never type the
suffix yourself after a slot. Example: `{PERSON1.first+DAT} ilet` → `Mehmet'e ilet`.

## What makes a template good

- **Realistic**: what a real employee, doctor, lawyer, HR specialist, teacher, developer,
  sales rep or student would type. Imperatives to the AI ("özetle", "daha kibar yaz",
  "rewrite", "translate to English", "tabloya dök") are typical.
- **Varied**: sentence-initial and mid-sentence names, names next to punctuation, in lists,
  in parentheses, in quotes, in email signatures, in greetings ("Merhaba {PERSON1.first},"),
  in tables (Markdown/CSV), in JSON/YAML/log lines, in code comments and string literals,
  in chat transcripts ("[10:42] {PERSON1.first}: ..."), all-caps headers, lower-case typing.
- **Hard negatives are essential** — write them as plain text (no slot), next to real slots:
  - Turkish common words that are also names: deniz, güneş, umut, barış, can, ay, kaya, demir,
    yıldız, bahar, ekim, ilkay, şeker, aslan, kartal, çiçek, nur, savaş, sevgi, gül — used as
    ordinary words ("deniz kenarında", "demir yolu", "umut ediyorum", "barış görüşmesi").
  - Companies/brands/products that contain surnames: Koç Holding, Sabancı Üniversitesi,
    Yıldız Teknik, Ford, Dell, Tesla, McDonald's, Johnson & Johnson, Mercedes-Benz.
  - Institutions, departments, job titles, software names, month/day names (Mart, Haziran,
    Monday), capitalised sentence starts, code identifiers (`UserName`, `getFullName()`).
  - Generic placeholders: "müşteri", "the patient", "John Doe" in a code example is still a
    PERSON slot — when in doubt, a human name is a slot.
- **Also write ~15% templates with no slot at all** (fully benign prompts with hard negatives).
- Public figures are still people: put them in a PERSON slot when they appear (the product
  masks every person name and restores it in the answer, so over-masking is cheap).
- Never use real private individuals. Literal e-mails/phones must use example domains
  (`example.com`, `example.org`, `ornek.com.tr`) and obviously synthetic numbers.

Output **only** valid JSONL lines (one object per line, no comments, no trailing commas).

## Distractor slots (negatives) — `{NEG:<kind>}`

A distractor slot is filled with a capitalised name that is **not** personal data and is
labelled `O`. It teaches the model that a capitalised word is not automatically a person.
Kinds (pools in `data/pools/distractors.json`):

| kind | examples |
|---|---|
| `tech` | Django, Kafka, Jenkins, Jackson, Airflow, Kubernetes, Hibernate, Spring Boot, NetSuite, SAP, Logo Tiger |
| `ai` | Claude, Gemini, ChatGPT, Copilot, Siri, Alexa, Llama, Mistral |
| `org` | Koç Holding, Aselsan, Arçelik, Turkcell, Garanti BBVA, Siemens, Johnson & Johnson, Ford Otosan |
| `brand` | Canon, Tesla, Nike, Mavi, LC Waikiki, Ülker, Pınar, McDonald's |
| `institution` | Mehmet Akif Ersoy Üniversitesi, Bilkent, Hacettepe, Acıbadem, Atatürk Anadolu Lisesi, Sabiha Gökçen Havalimanı |
| `law` | KVKK, Türk Borçlar Kanunu, GDPR, Sarbanes-Oxley Act, Dodd-Frank Act, Basel III, ISO 27001 |
| `eponym` | Dijkstra algoritması, Alzheimer, Parkinson, Behçet hastalığı, Asperger, Fibonacci, Gauss, Newton yasaları, Doppler |
| `place` | cities/regions/landmarks as a topic or destination, not a person's residence: Kapadokya, Kaz Dağları, Amalfi Coast, Lisbon, Rize, Mersin Limanı |
| `media` | Ekşi Sözlük, Netflix, Muhteşem Yüzyıl, Game of Thrones, Hürriyet |
| `club` | Fenerbahçe, Galatasaray, Beşiktaş, Real Madrid |
| `word` | Turkish/English words that are also given names, in lower or sentence case as ordinary words: deniz, umut, kaya, demir, barış, güneş, can, hope, will, may, grace |

`{NEG:<kind>}` takes `+SUFFIX` like any slot (`{NEG:org+DAT}` → "Arçelik'e"). Templates may (and
should) mix distractor slots with real `PERSON` slots, so the model learns to tell them apart in
the same sentence.
