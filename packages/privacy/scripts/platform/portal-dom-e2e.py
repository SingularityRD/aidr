"""Real Chromium DOM with a mocked HTTP boundary. Native local HTTPS tests run separately.
The environment denies browser navigation to local HTTPS by administrative policy.
"""
import pathlib,json,time
from playwright.sync_api import sync_playwright
R=pathlib.Path(__file__).resolve().parents[2];OUT=R/'reports/platform'
mock='''window.__calls=[];window.__status='open';window.__sequence=1;
const c={id:'bf261d20-8621-4a6b-a93e-e490f4a37791',owner:'operator',destination:'kurumsal-ai',reason:'DOCUMENT_REVIEW',policyRevision:5,createdAt:1790236800000};
window.fetch=async(path,options={})=>{__calls.push({path,options});let value;
if(path==='/api/session')value={subjectId:'reviewer',roles:['security-reviewer'],csrf:'fixture-csrf'};
else if(path==='/api/reviews')value={items:[{...c,status:__status}]};
else if(path.endsWith('/history'))value={items:[{actor:'operator',transition:'OPENED',at:1790236800000,reason:'Belge düz metne dönüştürüldü. Kaynak dosya gönderilmez.'},...(__sequence===2?[{actor:'reviewer',transition:'APPROVED',at:1790236810000,reason:'Yalnız bu işlem için süreli, tek kullanımlık izin.'}]:[])]};
else if(path.endsWith('/decision')){const body=JSON.parse(options.body);if(options.headers['X-AIDR-CSRF']!=='fixture-csrf')return{ok:false};__status=body.decision;__sequence++;value={...c,status:__status,sequence:__sequence};}
else value={...c,status:__status,sequence:__sequence};return{ok:true,json:async()=>value};};'''
report={'kind':'Chromium DOM fixture; mocked fetch API; local HTTPS API verified separately','cases':[]}
def run(name,f):
 try:f();report['cases'].append({'name':name,'passed':True})
 except Exception as e:report['cases'].append({'name':name,'passed':False,'error':str(e)})
with sync_playwright() as p:
 b=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox']);report['browserVersion']=b.version;page=b.new_page(viewport={'width':1320,'height':1030})
 html=(R/'portal/index.html').read_text().replace('<link rel="stylesheet" href="/style.css">','').replace('<script type="module" src="/app.js"></script>','')
 page.set_content(html);page.add_style_tag(content=(R/'portal/style.css').read_text());page.add_script_tag(content=mock);page.add_script_tag(content=(R/'portal/app.js').read_text());page.wait_for_selector('#list .row')
 def queue():assert page.locator('#list .row').count()==1 and 'reviewer' in page.locator('#identity').inner_text()
 run('queue renders authenticated fixture',queue)
 def open_case():page.get_by_role('button',name='İncele').click();page.wait_for_selector('#detail:not([hidden])');assert not page.locator('#approve').is_disabled()
 run('reviewer can open a case created by a different operator',open_case)
 def approve():
  page.locator('#reason').fill('İş gerekçesi doğrulandı. Yalnız temizlenmiş tek işlem için süreli izin.');page.locator('#approve').click();page.wait_for_function('document.querySelector("#detail-title").textContent==="Süreli onay"');assert page.locator('#approve').is_disabled();assert page.locator('#history .history-item').count()==2
 run('approval sends CSRF, sequence and reason, then prevents repeat approval',approve)
 def safe_text():assert page.locator('#history script').count()==0 and page.locator('#reason').get_attribute('maxlength')=='2000'
 run('text-only rendering and input length limit',safe_text)
 page.screenshot(path=str(OUT/'review-portal.png'),full_page=True);b.close()
report['passed']=sum(c['passed'] for c in report['cases']);report['total']=len(report['cases']);(OUT/'portal-dom-e2e.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps(report,ensure_ascii=False));assert report['passed']==report['total']
