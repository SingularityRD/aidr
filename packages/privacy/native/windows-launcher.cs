// Build-time paths are inserted by build-windows.ps1 (or the companion installer,
// src/companion) after safe base64 encoding. Windows-only launcher; exercised on Windows 11
// through the companion's verify step and Chrome (packages/privacy/README.md).
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
internal static class AIDRNativeLauncher {
 static string Decode(string value) { return Encoding.UTF8.GetString(Convert.FromBase64String(value)); }
 static string Quote(string value) {
  if(value.IndexOf('\0')>=0)throw new ArgumentException();
  var b=new StringBuilder("\"");int slashes=0;
  foreach(char c in value){if(c=='\\'){slashes++;continue;}if(c=='"'){b.Append('\\',slashes*2+1);b.Append(c);}else{b.Append('\\',slashes);b.Append(c);}slashes=0;}
  b.Append('\\',slashes*2);return b.Append('"').ToString();
 }
 static void Pump(Stream from, Stream to) {
  var buffer=new byte[65536];int n;
  while((n=from.Read(buffer,0,buffer.Length))>0){to.Write(buffer,0,n);to.Flush();}
 }
 static int Main(string[] args) {
  Process child=null;
  try {
   string node=Decode("__NODE_BASE64__"),host=Decode("__HOST_BASE64__"),config=Decode("__CONFIG_BASE64__");
   var arguments=new StringBuilder(Quote(host)+" --config "+Quote(config));foreach(var arg in args)arguments.Append(' ').Append(Quote(arg));
   child=Process.Start(new ProcessStartInfo(node,arguments.ToString()){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true});
   if(child==null)return 2;
   // Native messaging frames are small and request/response: every chunk must be flushed at once.
   // (Stream.CopyToAsync into Process.StandardInput.BaseStream buffers 4 KiB and stalled `hello`.)
   var input=Task.Run(delegate {try{Pump(Console.OpenStandardInput(),child.StandardInput.BaseStream);}catch{}finally{try{child.StandardInput.Close();}catch{}}});
   var output=Task.Run(delegate {try{Pump(child.StandardOutput.BaseStream,Console.OpenStandardOutput());}catch{}});
   // Drain stderr without forwarding paths or arbitrary child diagnostics.
   var error=child.StandardError.BaseStream.CopyToAsync(Stream.Null);
   child.WaitForExit();Task.WaitAll(output,error);return child.ExitCode;
  }catch{return 2;}finally{if(child!=null){try{if(!child.HasExited)child.Kill();}catch{}child.Dispose();}}
 }
}
