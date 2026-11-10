import json,pathlib,sys,datetime,concurrent.futures
sys.path.insert(0,'/home/wing/Documents/Codex/2026-10-31/new-realtime-voice-chat-6/.local/acs-origin-test')
from acs_api import request
W=pathlib.Path(__file__).resolve().parent
P=W/'run.json'
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(s):P.write_text(json.dumps(s,ensure_ascii=False,indent=2))
def scan_case(case,phase):
 start=now();x=request('POST','/v1/images/scan',{'imageName':case['appScanReference'],'force':True},timeout=240,token_key='scan_token')
 (W/(phase+'-python-'+case['minor'].replace('.','')+'.json')).write_text(json.dumps(x,ensure_ascii=False,indent=2))
 assert x['id']==case['appManifest']['manifestDigest'],('digest mismatch',x.get('id'))
 assert x['metadata']['v1']['digest']==case['appManifest']['configDigest']
 assert x['metadata']['layerShas']==case['appManifest']['layers']
 result={'minor':case['minor'],'requestStarted':start,'responseReceived':now(),'scanTime':x.get('scan',{}).get('scanTime'),'appDigest':x['id'],'appConfigDigest':x['metadata']['v1']['digest'],'baseMatches':x.get('baseImageInfo',[]),'scanNotes':x.get('scan',{}).get('notes',[]),'metadataLayerCount':len(x['metadata']['layerShas'])}
 print(json.dumps(result,ensure_ascii=False),flush=True);return result
s=json.loads(P.read_text());phase=sys.argv[1]
if phase=='baseline':
 assert s.get('allImagesPreparedAt')
 refs=request('GET','/v2/baseimages',admin=True,timeout=20);assert not any(s['runId'] in str(x) for x in refs.get('baseImageReferences',[]))
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda c:scan_case(c,'baseline'),s['cases']))
 assert all(not x['baseMatches'] for x in results),'Unexpected known base before registration'
 s['baseline']=results;s['baselineVerifiedAt']=now();save(s);print('BASELINE PASS: neither old app has a recognized base',flush=True)
elif phase=='register':
 minor=sys.argv[2];assert s.get('baselineVerifiedAt');case=next(c for c in s['cases'] if c['minor']==minor)
 assert not case.get('registration')
 refs=request('GET','/v2/baseimages',admin=True,timeout=20)
 assert not any(x.get('baseImageRepoPath')==case['baseRegistryRepo'] for x in refs.get('baseImageReferences',[]))
 case['registrationRequestedAt']=now();assert case['registrationRequestedAt']>s['allImagesPreparedAt']
 payload={'baseImageRepoPath':case['baseRegistryRepo'],'baseImageTagPattern':case['baseTag']}
 result=request('POST','/v2/baseimages',payload,admin=True,timeout=30)
 case['registration']=result['baseImageReference'];case['registrationCompletedAt']=now();save(s)
 print(json.dumps({'registeredAfterAppBuild':True,'minor':minor,'registrationRequestedAt':case['registrationRequestedAt'],'registration':case['registration']},ensure_ascii=False),flush=True)
elif phase=='scan':
 label=sys.argv[2]
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda c:scan_case(c,label),s['cases']))
 s[label]=results;save(s)
else:raise ValueError(phase)
