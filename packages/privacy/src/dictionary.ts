import { normalize } from './normalize.js';
import { fail } from './errors.js';
import type { EntityType, LiteralRule } from './types.js';
interface Node { next:Map<string,number>; fail:number; out:{length:number;type:EntityType}[]; }
/** Bounded Aho-Corasick literal matcher. No administrator/user supplied regex execution. */
export class LiteralMatcher {
  private readonly nodes: Node[]=[{next:new Map(),fail:0,out:[]}];
  constructor(rules:readonly LiteralRule[]) {
    let total=0;
    if(rules.length>1024) fail('DICTIONARY_LIMIT');
    for(const rule of rules) {
      const s=normalize(rule.value).text.toLocaleLowerCase('tr'); total+=s.length;
      if(!s.trim()||s.length>256||total>65536) fail('DICTIONARY_LIMIT');
      let state=0;
      for(const c of s) {
        if(!this.nodes[state]!.next.has(c)) {
          this.nodes[state]!.next.set(c,this.nodes.length);
          this.nodes.push({next:new Map(),fail:0,out:[]});
        }
        state=this.nodes[state]!.next.get(c)!;
      }
      this.nodes[state]!.out.push({length:[...s].length,type:rule.type});
    }
    const q=[...this.nodes[0]!.next.values()];
    for(let i=0;i<q.length;i++) {
      const r=q[i]!;
      for(const [c,u] of this.nodes[r]!.next) {
        q.push(u);let v=this.nodes[r]!.fail;
        while(v && !this.nodes[v]!.next.has(c)) v=this.nodes[v]!.fail;
        this.nodes[u]!.fail=this.nodes[v]!.next.get(c)??0;
        this.nodes[u]!.out.push(...this.nodes[this.nodes[u]!.fail]!.out);
      }
    }
  }
  scan(text:string,emit:(start:number,end:number,type:EntityType)=>void):void {
    // Character-wise lowercasing with an offset map (U+0130 can change length).
    const chars:string[]=[],starts:number[]=[],ends:number[]=[];let offset=0;
    for(const raw of text) {
      for(const c of raw.toLocaleLowerCase('tr')) {chars.push(c);starts.push(offset);ends.push(offset+raw.length);}
      offset+=raw.length;
    }
    let state=0;
    for(let i=0;i<chars.length;i++) {
      const c=chars[i]!;
      while(state&&!this.nodes[state]!.next.has(c)) state=this.nodes[state]!.fail;
      state=this.nodes[state]!.next.get(c)??0;
      for(const match of this.nodes[state]!.out) emit(starts[i-match.length+1]!,ends[i]!,match.type);
    }
  }
}
