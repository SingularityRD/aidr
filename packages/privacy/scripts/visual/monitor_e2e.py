"""Diagnostic sampled RSS, not a module memory guarantee or load benchmark."""
import json
import subprocess
import time
import psutil
from pathlib import Path
peak_sum=peak_child=peak_node=0
with open('reports/visual/e2e-console.txt','w') as log:
    p=subprocess.Popen(['node','scripts/visual/e2e.mjs'],stdout=log,stderr=subprocess.STDOUT)
    root=psutil.Process(p.pid)
    while p.poll() is None:
        total=0
        try:processes=[root]+root.children(recursive=True)
        except psutil.Error:processes=[]
        for proc in processes:
            try:
                rss=proc.memory_info().rss;total+=rss
                if proc.pid==p.pid:peak_node=max(peak_node,rss)
                else:peak_child=max(peak_child,rss)
            except psutil.Error:pass
        peak_sum=max(peak_sum,total);time.sleep(.05)
    code=p.wait()
Path('reports/visual/e2e-memory.json').write_text(json.dumps(dict(sampleIntervalMs=50,peakNodeRssBytes=peak_node,peakSingleChildRssBytes=peak_child,peakSumOfProcessRssBytes=peak_sum,note='Sum RSS may double-count shared pages; Python+OCR included. Cold per-stage workers; no concurrency benchmark.',exitCode=code),indent=2))
raise SystemExit(code)
