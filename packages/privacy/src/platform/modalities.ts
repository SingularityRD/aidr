import { bytesDigest } from './state.js';
import { deny, integer } from '../enterprise/util.js';
import type { Span } from './evaluation.js';
export interface TimedWord {text:string;startMs:number;endMs:number;confidence:number;}
export interface TrustedTranscript {audioSha256:string;modelSha256:string;language:'tr'|'en';complete:boolean;words:readonly TimedWord[];}
export interface AudioResult {decision:'review'|'redact';output:Buffer|null;reviewArtifact:Buffer|null;redactedRanges:readonly {startFrame:number;endFrame:number}[];reason:string;}
interface Wav {sampleRate:number;channels:number;frames:number;pcm:Buffer;}
function parseWav(input:Uint8Array):Wav{
 const b=Buffer.from(input);if(b.length<44||b.length>16777216||b.toString('ascii',0,4)!=='RIFF'||b.toString('ascii',8,12)!=='WAVE'||b.readUInt32LE(4)!==b.length-8)deny('AUDIO_FORMAT');let offset=12,fmt:Buffer|null=null,data:Buffer|null=null;
 while(offset+8<=b.length){const tag=b.toString('ascii',offset,offset+4),n=b.readUInt32LE(offset+4);offset+=8;if(offset+n>b.length)deny('AUDIO_CHUNK');if(tag==='fmt '){if(fmt)deny('AUDIO_DUPLICATE');fmt=b.subarray(offset,offset+n);}else if(tag==='data'){if(data)deny('AUDIO_DUPLICATE');data=b.subarray(offset,offset+n);}offset+=n+(n%2);}
 if(offset!==b.length||!fmt||fmt.length!==16||!data||fmt.readUInt16LE(0)!==1||fmt.readUInt16LE(14)!==16)deny('AUDIO_PCM16_REQUIRED');const channels=fmt.readUInt16LE(2),sampleRate=fmt.readUInt32LE(4),align=fmt.readUInt16LE(12);if(![1,2].includes(channels)||sampleRate<8000||sampleRate>48000||align!==channels*2||fmt.readUInt32LE(8)!==sampleRate*align||data.length%align||data.length/align/sampleRate>120)deny('AUDIO_LIMIT');return {channels,sampleRate,frames:data.length/align,pcm:Buffer.from(data)};
}
function encode(w:Wav):Buffer{const out=Buffer.alloc(44+w.pcm.length);out.write('RIFF');out.writeUInt32LE(out.length-8,4);out.write('WAVEfmt ',8);out.writeUInt32LE(16,16);out.writeUInt16LE(1,20);out.writeUInt16LE(w.channels,22);out.writeUInt32LE(w.sampleRate,24);out.writeUInt32LE(w.sampleRate*w.channels*2,28);out.writeUInt16LE(w.channels*2,32);out.writeUInt16LE(16,34);out.write('data',36);out.writeUInt32LE(w.pcm.length,40);w.pcm.copy(out,44);return out;}
/** Trust boundary: recognizer callback is administrator-controlled, not request subtitles.
 * PII-only audio still contains voice identity, so ALWAYS requires human review.
 * reviewArtifact is solely for an authorized review UI, NEVER for provider egress.
 * A real ASR model is not shipped; intervals are tested independently of recognition quality. */
export class AudioPrivacy {
 constructor(private o:{mode:'silence-all'|'pii-intervals';recognize?:(bytes:Uint8Array)=>Promise<TrustedTranscript>;modelSha256?:string;detect?:(text:string)=>Promise<readonly Span[]>}){}
 async protect(input:Uint8Array):Promise<AudioResult>{const original=Buffer.from(input),wav=parseWav(original);if(this.o.mode==='silence-all'){wav.pcm.fill(0);return {decision:'redact',output:encode(wav),reviewArtifact:null,redactedRanges:[{startFrame:0,endFrame:wav.frames}],reason:'ALL_AUDIO_REMOVED'};}
  if(!this.o.recognize||!this.o.detect||!this.o.modelSha256)deny('ASR_REQUIRED');const r=await this.o.recognize(Buffer.from(original));
  if(!r.complete||r.audioSha256!==bytesDigest(original)||r.modelSha256!==this.o.modelSha256||!['tr','en'].includes(r.language)||r.words.length>10000||!r.words.length)deny('ASR_UNVERIFIED');let text='',last=0;const positions:{start:number;end:number;word:TimedWord}[]=[];
  for(const word of r.words){if(typeof word.text!=='string'||!word.text.length||word.text.length>500||!Number.isFinite(word.startMs)||!Number.isFinite(word.endMs)||word.startMs<last||word.endMs<=word.startMs||word.endMs>wav.frames*1000/wav.sampleRate||!Number.isFinite(word.confidence)||word.confidence<.85||word.confidence>1)deny('ASR_UNCERTAIN');last=word.endMs;const start=text.length;text+=word.text;positions.push({start,end:text.length,word});text+=' ';}
  const spans=await this.o.detect(text.trimEnd()),ranges:{startFrame:number;endFrame:number}[]=[];
  for(const span of spans){integer(span.start,0,text.length);integer(span.end,span.start+1,text.length);const words=positions.filter(p=>p.end>span.start&&p.start<span.end);if(!words.length)deny('ASR_OFFSETS');const startFrame=Math.max(0,Math.floor((words[0]!.word.startMs-150)*wav.sampleRate/1000)),endFrame=Math.min(wav.frames,Math.ceil((words.at(-1)!.word.endMs+150)*wav.sampleRate/1000));wav.pcm.fill(0,startFrame*wav.channels*2,endFrame*wav.channels*2);ranges.push({startFrame,endFrame});}
  return {decision:'review',output:null,reviewArtifact:encode(wav),redactedRanges:ranges,reason:'VOICE_IDENTITY_AND_ASR_REQUIRE_REVIEW'};
 }
}
/** Reject sampling-only video evidence. This validates an adapter's coverage manifest, not
 * the truth of a decoder or detector; actual video decoding/transcoding is NOT supplied. */
export function requireCompleteVideoCoverage(totalFrames:number,scannedFrameIds:readonly number[],audioScanned:boolean):void{
 integer(totalFrames,1,18000);if(!audioScanned||scannedFrameIds.length!==totalFrames)deny('VIDEO_INCOMPLETE');for(let i=0;i<totalFrames;i++)if(scannedFrameIds[i]!==i)deny('VIDEO_FRAME_GAP');
}
export function unsupportedModalityPolicy(kind:string):{decision:'block';reason:string}{return {decision:'block',reason:['face','signature','handwriting','cad','steganography','video'].includes(kind)?'SPECIALIST_DETECTOR_REQUIRED':'UNSUPPORTED_MODALITY'};}
