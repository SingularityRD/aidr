/** Plain-text serialization with caret mapping; rich formatting is intentionally not preserved.
 * Block boundaries become newlines, avoiding accidental concatenation of adjacent form fields. */
export function editableSnapshot(el:HTMLElement):{text:string;start:number;end:number} {
  if(el instanceof HTMLTextAreaElement||el instanceof HTMLInputElement)return {text:el.value,start:el.selectionStart??el.value.length,end:el.selectionEnd??el.value.length};
  let text='';const offsets=new Map<Node,number[]>();
  const visit=(node:Node):void=>{
    const points:number[]=[text.length];offsets.set(node,points);
    if(node.nodeType===Node.TEXT_NODE){const value=node.nodeValue??'';const base=text.length;text+=value;for(let i=1;i<=value.length;i++)points.push(base+i);return;}
    if(node instanceof HTMLElement&&node.tagName==='BR'){text+='\n';points.push(text.length);return;}
    const children=[...node.childNodes];
    for(let i=0;i<children.length;i++){
      const child=children[i]!;visit(child);
      if(child instanceof HTMLElement&&['P','DIV','LI','TR','PRE'].includes(child.tagName)&&i<children.length-1&&!text.endsWith('\n'))text+='\n';
      points.push(text.length);
    }
  };visit(el);
  const selection=el.ownerDocument.getSelection();let start=text.length,end=text.length;
  if(selection&&selection.rangeCount){const range=selection.getRangeAt(0),a=offsets.get(range.startContainer)?.[range.startOffset],b=offsets.get(range.endContainer)?.[range.endOffset];
    if(a!==undefined&&b!==undefined){start=Math.min(a,b);end=Math.max(a,b);}}
  return {text,start,end};
}
export function replaceEditable(el:HTMLElement,text:string):void {
  el.focus();
  if(el instanceof HTMLTextAreaElement){const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value')?.set;if(!setter)throw new Error('EDITOR_UNSUPPORTED');setter.call(el,text);el.setSelectionRange(text.length,text.length);}
  else if(el instanceof HTMLInputElement){const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')?.set;if(!setter)throw new Error('EDITOR_UNSUPPORTED');setter.call(el,text);}
  else {el.replaceChildren(document.createTextNode(text));const sel=window.getSelection(),range=document.createRange();range.selectNodeContents(el);range.collapse(false);sel?.removeAllRanges();sel?.addRange(range);}
  el.dispatchEvent(new InputEvent('input',{bubbles:true,composed:true,inputType:'insertText',data:null}));
}
