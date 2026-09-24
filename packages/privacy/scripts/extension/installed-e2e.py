#!/usr/bin/env python3
"""Opt-in installed MV3 smoke test on a permitted developer machine.
Authenticated live provider UI and native OS registration are not tested here.
Never edits enterprise browser policies. Fixture responses contain synthetic data.
"""
import os,json,tempfile,sys
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[2]
if os.environ.get('AIDR_RUN_INSTALLED_EXTENSION')!='1':
 print('NOT RUN: set AIDR_RUN_INSTALLED_EXTENSION=1 on an administrator-approved test machine.');sys.exit(77)
extension=ROOT/'extension/chrome';identity=json.loads((ROOT/'extension/identity.json').read_text())['extensionId']
report={'scope':'installed unpacked MV3 + synthetic provider fixtures; no live account or OS native-host registration','cases':[]}
with tempfile.TemporaryDirectory(prefix='aidr-installed-') as profile, sync_playwright() as p:
 options={'headless':True,'args':[f'--disable-extensions-except={extension}',f'--load-extension={extension}']}
 if os.environ.get('AIDR_CHROMIUM_EXECUTABLE'):options['executable_path']=os.environ['AIDR_CHROMIUM_EXECUTABLE']
 else:options['channel']='chromium'
 context=p.chromium.launch_persistent_context(profile,**options)
 try:
  worker=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker',timeout=15000)
  assert worker.url.startswith('chrome-extension://'+identity+'/'),worker.url
  fixtures={
   'chatgpt.com':'<textarea id="prompt-textarea"></textarea><button type="button" data-testid="send-button">Send</button>',
   'gemini.google.com':'<rich-textarea><div contenteditable="true" class="ql-editor"></div></rich-textarea><button type="button" class="send-button">Send</button>',
   'claude.ai':'<div contenteditable="true" class="ProseMirror" data-placeholder="Reply"></div><button type="button" aria-label="Send Message">Send</button>'}
  from urllib.parse import urlparse
  def route(r):
   host=urlparse(r.request.url).hostname
   if host in fixtures:r.fulfill(status=200,content_type='text/html',body='<style>textarea,[contenteditable]{display:block;width:600px;height:150px;border:1px solid}</style>'+fixtures[host])
   else:r.abort()
  context.route('**/*',route)
  for host in fixtures:
   page=context.new_page();page.goto('https://'+host+'/aidr-synthetic-fixture');page.wait_for_selector('#aidr-guard-status');page.wait_for_function("document.querySelector('#aidr-guard-status').dataset.aidrState==='ready'")
   page.locator('textarea,[contenteditable]').fill('Email: synthetic@example.com');page.wait_for_function("document.querySelector('#aidr-guard-status').dataset.aidrState==='sensitive'")
   page.evaluate("window.sent=false;document.querySelector('button').addEventListener('click',()=>window.sent=true)");page.locator('button').first.click();page.wait_for_timeout(100);assert not page.evaluate('window.sent');report['cases'].append({'provider':host,'pass':True});page.close()
  composer=context.new_page();composer.goto(f'chrome-extension://{identity}/compose.html');assert composer.locator('#raw').count()==1;report['cases'].append({'case':'extension-origin composer loads under real CSP','pass':True})
 finally:context.close()
report['passed']=len(report['cases']);report['total']=len(report['cases']);(ROOT/'reports/browser/installed-e2e.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
