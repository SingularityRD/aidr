export const PROVIDERS={
  chatgpt:{label:'ChatGPT',hosts:['chatgpt.com','chat.openai.com'],
    editors:['#prompt-textarea','textarea[data-id="root"]','textarea[data-testid="prompt-textarea"]'],
    send:['button[data-testid="send-button"]','button[aria-label="Send prompt"]','button[aria-label="Mesaj gönder"]']},
  gemini:{label:'Gemini',hosts:['gemini.google.com'],
    editors:['rich-textarea .ql-editor[contenteditable="true"]','rich-textarea [contenteditable="true"]','textarea[data-testid="gemini-prompt"]'],
    send:['button.send-button','button[aria-label="Send message"]','button[aria-label="Gönder"]']},
  claude:{label:'Claude',hosts:['claude.ai'],
    editors:['[contenteditable="true"][data-placeholder]','[contenteditable="true"].ProseMirror','textarea[data-testid="claude-prompt"]'],
    send:['button[aria-label="Send message"]','button[aria-label="Send Message"]']},
} as const;
export type Provider=keyof typeof PROVIDERS;
export const PROVIDER_IDS=Object.keys(PROVIDERS) as Provider[];
export const MATCHES=PROVIDER_IDS.flatMap(p=>PROVIDERS[p].hosts.map(h=>`https://${h}/*`));
/** Exact HTTPS origins only: no suffix matching, alternate ports, credentials or lookalikes. */
export function providerForUrl(raw:unknown):Provider|null {
  if(typeof raw!=='string'||raw.length>8192)return null;
  try{const u=new URL(raw);if(u.protocol!=='https:'||u.port||u.username||u.password)return null;
    for(const p of PROVIDER_IDS)if((PROVIDERS[p].hosts as readonly string[]).includes(u.hostname))return p;
  }catch{}return null;
}
export function approvedOrigin(raw:unknown):string|null {try{return providerForUrl(raw)?new URL(raw as string).origin:null;}catch{return null;}}
