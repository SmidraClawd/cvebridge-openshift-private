import json,pathlib,subprocess,datetime
W=pathlib.Path(__file__).resolve().parent;P=W/'run.json';s=json.loads(P.read_text());ns=s['runId']
K=['kubectl','--kubeconfig','/home/wing/Documents/Codex/2026-10-31/new-realtime-voice-chat-4/.local/kubeconfig']
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def run(args):return subprocess.run(K+args,capture_output=True,text=True,check=True)
assert not run(['get','namespace',ns,'--ignore-not-found','-o','name']).stdout.strip()
orig=json.loads(run(['get','deployments','-A','-o','json']).stdout)
(W/'original-deployments.json').write_text(json.dumps([{'namespace':d['metadata']['namespace'],'name':d['metadata']['name'],'uid':d['metadata']['uid'],'generation':d['metadata']['generation'],'images':[c['image'] for c in d['spec']['template']['spec']['containers']]} for d in orig['items']],indent=2))
items=[{'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns,'labels':{'cvebridge-test':'late-base-detection'}}}]
for c in s['cases']:
 name='app-python-'+c['minor'].replace('.','')
 items.append({'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':name,'namespace':ns,'labels':{'cvebridge-test':'late-base-detection'}},'spec':{'replicas':1,'selector':{'matchLabels':{'app':name}},'template':{'metadata':{'labels':{'app':name,'cvebridge-test':'late-base-detection'}},'spec':{'automountServiceAccountToken':False,'securityContext':{'runAsNonRoot':True,'runAsUser':65534,'runAsGroup':65534,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'app','image':c['appScanReference'],'imagePullPolicy':'IfNotPresent','command':['python','-B','-c','import time; time.sleep(3600)'],'resources':{'requests':{'cpu':'10m','memory':'16Mi'},'limits':{'cpu':'100m','memory':'64Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}}}})
manifest=W/'test-workloads.json';manifest.write_text(json.dumps({'apiVersion':'v1','kind':'List','items':items},indent=2))
s['testNamespace']=ns;s['workloadDeploymentStarted']=now();P.write_text(json.dumps(s,ensure_ascii=False,indent=2));print(run(['apply','-f',str(manifest)]).stdout,flush=True)
for c in s['cases']:
 name='app-python-'+c['minor'].replace('.','');print(run(['rollout','status','deployment/'+name,'-n',ns,'--timeout=45s']).stdout,flush=True)
pods=json.loads(run(['get','pods','-n',ns,'-o','json']).stdout)
s['runningTestPods']=[{'name':p['metadata']['name'],'created':p['metadata']['creationTimestamp'],'phase':p['status']['phase'],'images':[a['image'] for a in p['spec']['containers']],'imageIDs':[a['imageID'] for a in p['status']['containerStatuses']]} for p in pods['items']]
assert len(s['runningTestPods'])==2 and all(p['phase']=='Running' for p in s['runningTestPods'])
s['workloadsReadyAt']=now();P.write_text(json.dumps(s,ensure_ascii=False,indent=2));print(json.dumps(s['runningTestPods'],ensure_ascii=False),flush=True)
