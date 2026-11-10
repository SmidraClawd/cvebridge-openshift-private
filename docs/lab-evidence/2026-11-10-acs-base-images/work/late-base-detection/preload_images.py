import json,pathlib,subprocess,datetime
W=pathlib.Path(__file__).resolve().parent;P=W/'run.json';s=json.loads(P.read_text());K=['kubectl','--kubeconfig','/home/wing/Documents/Codex/2026-10-31/new-realtime-voice-chat-4/.local/kubeconfig']
svc=json.loads(subprocess.check_output(K+['get','service','origin-registry','-n','cvebridge-origin-test','-o','json'],text=True));host=svc['spec']['clusterIP']+':5000'
log=W/'preload.log'
for c in s['cases']:
 direct=host+'/'+c['appRepo']+'@'+c['appManifest']['manifestDigest']
 with log.open('a') as f:
  subprocess.run(['sudo','-n','docker','exec','k3d-cvebridge-server-0','ctr','-n','k8s.io','images','pull','--plain-http','--platform','linux/amd64',direct],stdout=f,stderr=subprocess.STDOUT,check=True)
  subprocess.run(['sudo','-n','docker','exec','k3d-cvebridge-server-0','ctr','-n','k8s.io','images','tag',direct,c['appScanReference']],stdout=f,stderr=subprocess.STDOUT,check=True)
 print('PRELOADED',c['minor'],c['appManifest']['manifestDigest'],flush=True)
 name='app-python-'+c['minor'].replace('.','');subprocess.run(K+['rollout','restart','deployment/'+name,'-n',s['testNamespace']],check=True)
for c in s['cases']:
 name='app-python-'+c['minor'].replace('.','');subprocess.run(K+['rollout','status','deployment/'+name,'-n',s['testNamespace'],'--timeout=45s'],check=True)
pods=json.loads(subprocess.check_output(K+['get','pods','-n',s['testNamespace'],'-o','json'],text=True))
s['runningTestPods']=[{'name':p['metadata']['name'],'created':p['metadata']['creationTimestamp'],'phase':p['status']['phase'],'images':[a['image'] for a in p['spec']['containers']],'imageIDs':[a.get('imageID') for a in p['status'].get('containerStatuses',[])]} for p in pods['items'] if not p['metadata'].get('deletionTimestamp')]
assert len(s['runningTestPods'])==2 and all(p['phase']=='Running' for p in s['runningTestPods'])
s['workloadsReadyAt']=datetime.datetime.now(datetime.timezone.utc).isoformat();s['preloadMethod']='Pulled existing HTTP registry through its ClusterIP into containerd; aliases preserve original manifest digest. No node DNS or registry trust configuration changed.'
P.write_text(json.dumps(s,ensure_ascii=False,indent=2));print(json.dumps(s['runningTestPods'],ensure_ascii=False),flush=True)
