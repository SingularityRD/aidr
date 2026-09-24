# Singularity AIDR Browser Guard

Browser extension (Chrome, Edge, Firefox) that detects sensitive data in prompts,
pastes and files before they reach AI chat products (ChatGPT, Gemini, Claude,
Copilot, Perplexity, DeepSeek, Mistral, Grok), replaces it with reversible
placeholders such as `[EMAIL_1]`, and restores the originals locally in the
responses. Detection reuses the AIDR Privacy rule layer (`packages/privacy`).

Module contracts live in [`src/types.ts`](src/types.ts). Telemetry follows
[`docs/contracts/privacy-telemetry.md`](../../docs/contracts/privacy-telemetry.md).
