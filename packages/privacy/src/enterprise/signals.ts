import { detectionViews } from '../normalize.js';
/** Heuristic, bilingual triage only. No calibrated confidence, semantic completeness or promise
 * to defeat adaptive/multimodal prompt injection. Safe to bundle in the browser. */
export function inspectSignals(text:string):readonly string[] {
  if(typeof text!=='string'||text.length>1048576)throw new Error('SIGNAL_LIMIT');
  const codes=new Set<string>();
  for(const view of detectionViews(text)){
    const s=view.text.normalize('NFKC').toLowerCase().replace(/ı/gu,'i').replace(/i\u0307/gu,'i');
    if(/\bignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions?\b/u.test(s)
      ||/(?:önceki|onceki|sistem)\s+(?:tüm\s+|tum\s+)?(?:talimatlari|kurallari)\s+(?:yok\s+say|unut)/u.test(s))codes.add('INSTRUCTION_OVERRIDE');
    if(/\b(?:reveal|print|repeat|show)\s+(?:the\s+|your\s+)?(?:system|developer)\s+prompt\b/u.test(s)
      ||/sistem\s+(?:promptunu|talimatlarini|istemini)\s+(?:göster|goster|yaz|açikla|acikla)/u.test(s))codes.add('PROMPT_EXTRACTION');
    if(/(?:<\|(?:im_start|start_header_id|system)|\[inst\]|\[\/inst\])/u.test(s))codes.add('ROLE_DELIMITER');
    if(/(?:^|\n)\s*(?:system|developer)\s*:\s*(?:override|ignore|you are)/u.test(s))codes.add('ROLE_SPOOF');
    if(/<\s*(?:script|iframe|img|svg|object|embed|video|audio|link|meta)\b/u.test(s)||/!\s*\[[^\]\n]{0,2048}\]\s*\(/u.test(s)
      ||/\burl\s*\(\s*['"]?\s*(?:https?:|data:|\/\/)/u.test(s))codes.add('ACTIVE_CONTENT');
    const codeLines=(s.match(/(?:^|\n)\s*(?:export\s+)?(?:async\s+)?(?:function\s+[a-z_]|class\s+[a-z_]|def\s+[a-z_]|import\s+[a-z_{*]|from\s+[\w.]+\s+import|#include\s*[<"])/gu)??[]).length;
    if(codeLines>=2)codes.add('SOURCE_CODE_HINT');
  }
  return Object.freeze([...codes].sort());
}
export const COACHING_TR:Readonly<Record<string,string>>=Object.freeze({
  INSTRUCTION_OVERRIDE:'Metinde talimatları değiştirmeye yönelik bir kalıp bulundu. Alıntı veya güvenlik örneği de olabilir; onaylı inceleme yolunu kullanın.',
  PROMPT_EXTRACTION:'Sistem talimatlarının açığa çıkarılmasına yönelik bir kalıp bulundu.',
  SOURCE_CODE_HINT:'Kaynak kodu olabilecek içerik bulundu. Kuruma ait kod yalnız onaylı hedeflere gönderilmelidir.',
  ACTIVE_CONTENT:'Harici kaynak yükleyebilen işaretleme bulundu. Çıktıyı yalnız güvenli düz metin olarak işleyin.',
});
