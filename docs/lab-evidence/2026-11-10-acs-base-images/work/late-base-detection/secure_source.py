import json,pathlib,sys,datetime,urllib.request,hashlib,concurrent.futures
sys.path.insert(0,'/home/wing/Documents/Codex/2026-10-31/new-realtime-voice-chat-6/.local/acs-origin-test')
from acs_api import request
W=pathlib.Path(__file__).resolve().parent;P=W/'run.json';s=json.loads(P.read_text())
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save():P.write_text(json.dumps(s,ensure_ascii=False,indent=2))
HOST='registry.hub.docker.com';REPO=HOST+'/library/python'
def validate(c):
 with urllib.request.urlopen('https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull',timeout=30) as r:token=json.load(r)['token']
 headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'}
 def get(ref):
  with urllib.request.urlopen(urllib.request.Request('https://'+HOST+'/v2/library/python/manifests/'+ref,headers=headers),timeout=40) as r:return r.read()
 raw=get(c['tag']);j=json.loads(raw)
 if 'manifests' in j:
  m=next(m for m in j['manifests'] if m.get('platform',{}).get('os')=='linux' and m.get('platform',{}).get('architecture')=='amd64');raw=get(m['digest']);j=json.loads(raw)
 result={'minor':c['minor'],'verifiedAt':now(),'source':REPO+':'+c['tag'],'manifestDigest':'sha256:'+hashlib.sha256(raw).hexdigest(),'configDigest':j['config']['digest'],'layers':[l['digest'] for l in j['layers']]}
 assert result['manifestDigest']==c['mirroredBase']['manifestDigest']
 assert result['configDigest']==c['configDigest']
 assert result['layers']==c['mirroredBase']['layers']
 return result
mode=sys.argv[1]
if mode=='verify':
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:s['secureSourceVerification']=list(pool.map(validate,s['cases']))
 save();print(json.dumps(s['secureSourceVerification'],indent=2))
elif mode=='register-311':
 assert s.get('secureSourceVerification') and not s.get('secureIntegration')
 payload={'name':s['runId']+' Docker Hub HTTPS test','type':'docker','categories':['REGISTRY'],'docker':{'endpoint':'https://'+HOST,'insecure':False}}
 x=request('POST','/v1/imageintegrations',payload,admin=True,timeout=60)
 assert x.get('id'),x;s['secureIntegration']={'id':x['id'],'name':payload['name'],'endpoint':payload['docker']['endpoint']};save()
 s['secureRegistrationRequestedAt']=now();save()
 x=request('POST','/v2/baseimages',{'baseImageRepoPath':REPO,'baseImageTagPattern':'3.11.0-slim'},admin=True,timeout=30)
 s['secureReference']=x['baseImageReference'];s['secureRegistrationCompletedAt']=now();save()
 print(json.dumps({'integration':s['secureIntegration'],'reference':s['secureReference'],'at':s['secureRegistrationCompletedAt']}))
elif mode=='include-310':
 assert s.get('secureReference')
 s['securePatternExpandedAt']=now();save()
 request('PUT','/v2/baseimages/'+s['secureReference']['id'],{'baseImageTagPattern':'3.1[01].0-slim'},admin=True,timeout=30)
 s['secureExpandedPattern']='3.1[01].0-slim';save();print('Expanded only test reference to 3.1[01].0-slim at '+s['securePatternExpandedAt'])
else:raise ValueError(mode)
