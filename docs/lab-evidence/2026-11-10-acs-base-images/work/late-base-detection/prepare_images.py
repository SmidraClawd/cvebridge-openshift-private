import json,pathlib,subprocess,os,datetime,urllib.request,hashlib
W=pathlib.Path(__file__).resolve().parent
P=W/'run.json';state=json.loads(P.read_text());rid=state['runId']
LOG=W/'build.log'
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save():P.write_text(json.dumps(state,ensure_ascii=False,indent=2))
def run(args,env=None):
 with LOG.open('a') as f:
  f.write('\n'+now()+' '+repr(args)+'\n');f.flush()
  r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,text=True,env=env)
 if r.returncode:raise RuntimeError('Command failed: '+repr(args)+'; see build.log')
def manifest(repo,tag):
 headers={'Accept':'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'}
 def get(ref):
  with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:15000/v2/'+repo+'/manifests/'+ref,headers=headers),timeout=30) as r:return r.read()
 raw=get(tag);j=json.loads(raw);index='sha256:'+hashlib.sha256(raw).hexdigest()
 if 'manifests' in j:
  m=next(m for m in j['manifests'] if m.get('platform',{}).get('os')=='linux' and m.get('platform',{}).get('architecture')=='amd64');raw=get(m['digest']);j=json.loads(raw)
 return {'indexDigest':index,'manifestDigest':'sha256:'+hashlib.sha256(raw).hexdigest(),'configDigest':j['config']['digest'],'layers':[a['digest'] for a in j['layers']]}
for case in state['cases']:
 minor=case['minor'];short=minor.replace('.','');base_repo=rid+'/base-python-'+short;app_repo=rid+'/app-python-'+short
 case.update({'baseRepo':base_repo,'appRepo':app_repo,'baseRegistryRepo':'origin-registry.cvebridge-origin-test.svc:5000/'+base_repo,'baseTag':case['tag'],'appTag':'v1'})
 save();print('PULL',case['tag'],flush=True)
 run(['sudo','-n','docker','pull','--platform','linux/amd64',case['source']])
 local_base='localhost:15000/'+base_repo+':'+case['tag'];local_app='localhost:15000/'+app_repo+':v1'
 run(['sudo','-n','docker','tag',case['source'],local_base]);run(['sudo','-n','docker','push',local_base])
 case['mirroredBase']=manifest(base_repo,case['tag']);assert case['mirroredBase']['configDigest']==case['configDigest']
 ctx=W/('python-'+short);ctx.mkdir(exist_ok=True)
 (ctx/'app.py').write_text('import sys, ssl, json\nprint(json.dumps({"python":sys.version.split()[0], "tls":ssl.OPENSSL_VERSION, "purpose":"late base registration test"}))\n')
 (ctx/'Dockerfile').write_text('FROM '+case['source']+'\nCOPY app.py /opt/late-base/app.py\nCMD ["python", "-B", "/opt/late-base/app.py"]\n')
 case['appBuildStarted']=now();print('BUILD',minor,flush=True)
 run(['sudo','-n','docker','build','--no-cache','-t',local_app,str(ctx)],env=dict(os.environ,DOCKER_BUILDKIT='0'))
 case['appBuildFinished']=now();run(['sudo','-n','docker','push',local_app]);case['appPushed']=now()
 case['appManifest']=manifest(app_repo,'v1');assert case['appManifest']['layers'][:len(case['mirroredBase']['layers'])]==case['mirroredBase']['layers'];assert len(case['appManifest']['layers'])>len(case['mirroredBase']['layers'])
 case['appScanReference']='origin-registry.cvebridge-origin-test.svc:5000/'+app_repo+'@'+case['appManifest']['manifestDigest']
 result=subprocess.run(['sudo','-n','docker','run','--rm','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--cpus=1','--pids-limit=64','--user=65534:65534',local_app],capture_output=True,text=True,timeout=30)
 assert result.returncode==0,result.stderr;case['startup']=json.loads(result.stdout);case['imagesPreparedAt']=now();save()
 print(json.dumps({'minor':minor,'baseCreated':case['created'],'baseManifest':case['mirroredBase']['manifestDigest'],'appManifest':case['appManifest']['manifestDigest'],'appBuildFinished':case['appBuildFinished'],'startup':case['startup']}),flush=True)
state['allImagesPreparedAt']=now();save();print('ALL TEST IMAGES BUILT; NO BASE REGISTRATIONS ADDED YET',flush=True)
