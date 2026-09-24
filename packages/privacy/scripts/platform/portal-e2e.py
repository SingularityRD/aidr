import pathlib,subprocess,json,time,os
from playwright.sync_api import sync_playwright
ROOT=pathlib.Path(__file__).resolve().parents[2];OUT=ROOT/'reports/platform';OUT.mkdir(exist_ok=True)
server=subprocess.Popen(['node','scripts/platform/portal-server.mjs'],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
report={'kind':'real local HTTPS portal, real sessions/RBAC; synthetic offline IdP exchange','cases':[]}
def run(name,fn):
 t=time.perf_counter()
 try:fn();case={'name':name,'passed':True}
 except Exception as e:case={'name':name,'passed':False,'error':str(e)}
 case['elapsedMs']=round((time.perf_counter()-t)*1000,2);report['cases'].append(case)
try:
 line=server.stdout.readline()
 if not line:raise RuntimeError(server.stderr.read())
 cfg=json.loads(line)
 with sync_playwright() as p:
  browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox']);report['browserVersion']=browser.version
  context=browser.new_context(ignore_https_errors=True,viewport={'width':1360,'height':1100})
  context.add_cookies([{'name':'__Host-aidr-session','value':cfg['cookie'],'domain':'127.0.0.1','path':'/','secure':True,'httpOnly':True,'sameSite':'Lax'}]);page=context.new_page();page.on('console',lambda m:print('CONSOLE',m.type,m.text,flush=True));page.on('pageerror',lambda e:print('PAGEERROR',e,flush=True));page.goto(cfg['origin']);print('COOKIES',len(context.cookies()),flush=True);print('SESSION',context.request.get(cfg['origin']+'/api/session').text(),flush=True);page.wait_for_selector('#list .row',timeout=8000)
  def queue():
   assert page.locator('#list .row').count()==2
   assert 'bob' in page.locator('#identity').inner_text()
   assert page.locator('iframe').count()==0
  run('authenticated reviewer loads real encrypted review queue',queue)
  def csrf():
   code=page.evaluate('async id=>(await fetch("/api/reviews/"+id+"/decision",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({decision:"approved",reason:"Unauthorized CSRF attempt.",sequence:1})})).status',cfg['caseId'])
   assert code==403
  run('missing CSRF token rejected by actual server',csrf)
  def review():
   page.evaluate('id=>window.location.hash=id',cfg['caseId']);page.get_by_role('button',name='İncele').first.click();page.wait_for_selector('#detail:not([hidden])')
   page.locator('#reason').fill('İş gerekçesi doğrulandı; yalnız bu temizlenmiş işlem için tek kullanımlık izin.')
   page.locator('#approve').click();page.wait_for_function('document.querySelector("#detail-title").textContent==="Süreli onay"')
   assert page.locator('#approve').is_disabled();assert page.locator('#history .history-item').count()==2
   page.screenshot(path=str(OUT/'review-portal.png'),full_page=True)
  run('four-eyes time-limited approval persists and disables re-approval',review)
  def xss():
   assert page.locator('#history script').count()==0
   assert page.evaluate('document.querySelector("#reason").maxLength')==2000
   assert page.evaluate('document.cookie')==''
  run('history is text-only and session cookie is HttpOnly',xss)
  def unauthorized():
   other=browser.new_context(ignore_https_errors=True);res=other.request.get(cfg['origin']+'/api/reviews');assert res.status==403;other.close()
  run('unauthenticated browser cannot read review records',unauthorized)
  browser.close()
except Exception as e:
 report['fatalError']=str(e);print('FATAL',str(e),flush=True)
finally:
 server.terminate()
 try:server.wait(timeout=5)
 except subprocess.TimeoutExpired:server.kill()
 report['passed']=sum(c['passed'] for c in report['cases']);report['total']=len(report['cases']);(OUT/'portal-e2e.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n');print(json.dumps(report,ensure_ascii=False));
 if report['passed']!=report['total'] or report['total']<5:raise SystemExit(1)
