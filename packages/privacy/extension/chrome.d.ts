/** Narrow compile-time contract for APIs used here; runtime input is validated separately. */
interface ChromeSender { id?:string;url?:string;origin?:string;frameId?:number;documentId?:string;tab?:{id?:number;url?:string}; }
interface ChromeEvent<T extends (...args:any[])=>any>{addListener(fn:T):void;removeListener(fn:T):void;}
interface NativePort {postMessage(message:unknown):void;disconnect():void;onMessage:ChromeEvent<(message:any)=>void>;onDisconnect:ChromeEvent<()=>void>;}
interface ChromeTab {id?:number;url?:string;active?:boolean;windowId?:number;}
interface StorageArea {get(keys?:string|string[]|null):Promise<Record<string,any>>;set(items:Record<string,unknown>):Promise<void>;setAccessLevel(options:{accessLevel:'TRUSTED_CONTEXTS'}):Promise<void>;}
declare const chrome:{
 runtime:{id:string;lastError?:{message?:string};getURL(path:string):string;onMessage:ChromeEvent<(message:any,sender:ChromeSender,sendResponse:(response:any)=>void)=>boolean|void>;
  onInstalled:ChromeEvent<()=>void>;onStartup:ChromeEvent<()=>void>;sendMessage(message:unknown):Promise<any>;connectNative(name:string):NativePort;};
 storage:{managed:StorageArea;local:StorageArea;session:StorageArea;onChanged:ChromeEvent<(changes:Record<string,unknown>,area:string)=>void>;};
 tabs:{query(query:Record<string,unknown>):Promise<ChromeTab[]>;get(id:number):Promise<ChromeTab>;sendMessage(id:number,message:unknown,options?:{frameId?:number;documentId?:string}):Promise<any>;};
 windows:{create(options:Record<string,unknown>):Promise<unknown>;};
 action:{setBadgeText(options:{text:string;tabId?:number}):Promise<void>;setBadgeBackgroundColor(options:{color:string}):Promise<void>;};
 declarativeNetRequest:{updateDynamicRules(options:{removeRuleIds:number[];addRules:any[]}):Promise<void>;getDynamicRules():Promise<any[]>;};
};
