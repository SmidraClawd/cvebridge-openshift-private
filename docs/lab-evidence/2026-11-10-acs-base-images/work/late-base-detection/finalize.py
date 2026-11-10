import json,pathlib,sys,datetime,subprocess
sys.path.insert(0,'/home/wing/Documents/Codex/2026-10-31/new-realtime-voice-chat-6/.local/acs-origin-test')
from acs_api import request
W=pathlib.Path(__file__).resolve().parent;P=W/'run.json';s=json.loads(P.read_text())
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save():P.write_text(json.dumps(s,ensure_ascii=False,indent=2))
K=['kubectl','--kubeconfig','/home/wing/Documents/Codex/2026-10-31/new-realtime-voice-chat-4/.local/kubeconfig']
def kub(*args):return subprocess.run(K+list(args),text=True,capture_output=True,check=True).stdout
def deployments():
 return [{'namespace':d['metadata']['namespace'],'name':d['metadata']['name'],'uid':d['metadata']['uid'],'generation':d['metadata']['generation'],'images':[c['image'] for c in d['spec']['template']['spec']['containers']]} for d in json.loads(kub('get','deployments','-A','-o','json'))['items'] if d['metadata']['namespace']!=s['testNamespace']]
checks=[]
def check(ok,name):
 assert ok,name;checks.append(name)
baseline={r['minor']:r for r in s['baseline']}
first={r['minor']:r for r in s['after-https-311']}
final={r['minor']:r for r in s['after-https-both']}
native=json.loads((W/'after-https-both-rescan-native-summary.json').read_text())
before311=json.loads((W/'after-https-311-before-rescan-native-summary.json').read_text())
before310=json.loads((W/'after-https-both-before-rescan-native-summary.json').read_text())
check(all(not x['baseMatches'] for x in baseline.values()),'Both app images unrecognized before registration')
check(not first['3.10']['baseMatches'],'Negative control: 3.10 unrecognized while only 3.11 is registered')
for c in s['cases']:
 minor=c['minor'];result=final[minor]
 check(c['appBuildFinished']<s['secureRegistrationRequestedAt'],'App '+minor+' built before secure base registration')
 check(result['appDigest']==baseline[minor]['appDigest']==c['appManifest']['manifestDigest'],'App '+minor+' manifest unchanged')
 check(result['appConfigDigest']==baseline[minor]['appConfigDigest']==c['appManifest']['configDigest'],'App '+minor+' config unchanged')
 matches=result['baseMatches']
 check(len(matches)==1 and matches[0]['baseImageDigest']==c['mirroredBase']['manifestDigest'],'App '+minor+' matches exact historical base digest')
 check(matches[0]['baseImageFullName'].endswith(':'+c['tag']),'App '+minor+' matches correct historical tag')
 n=next(x for x in native['images'] if x['id']==result['appDigest'])
 check(n['baseMatches']==matches and n['metadataLayers']==c['appManifest']['layers'],'Native inventory agrees for '+minor)
check(all(not x['baseMatches'] for x in before311['images']),'Stored results still unrecognized before first explicit rescan')
check(not next(x for x in before310['images'] if 'app-python-310' in x['name']['fullName'])['baseMatches'],'Stored 3.10 result still unrecognized before second explicit rescan')
original=json.loads((W/'original-deployments.json').read_text())
check(sorted(deployments(),key=lambda x:x['uid'])==sorted(original,key=lambda x:x['uid']),'All original deployment UIDs, generations and images unchanged')
s['acsMetadata']=request('GET','/v1/metadata',timeout=30)
s['assertions']=checks;s['allAssertionsPassedAt']=now();save()
(W/'references-after-test-before-cleanup.json').write_text(json.dumps(request('GET','/v2/baseimages',admin=True),indent=2))
print('PASS: '+str(len(checks))+' assertions',flush=True)

# Remove only resources created by this isolated run, after preserving evidence.
ns=json.loads(kub('get','namespace',s['testNamespace'],'-o','json'))
assert ns['metadata']['labels']['cvebridge-test']=='late-base-detection'
assert s['testNamespace']==s['runId'] and s['runId'].startswith('late-base-')
print(kub('delete','namespace',s['testNamespace'],'--wait=true','--timeout=45s').strip(),flush=True)
refs=request('GET','/v2/baseimages',admin=True)['baseImageReferences']
to_delete=[c['registration'] for c in s['cases'] if c.get('registration')]+[s['secureReference']]
for own in to_delete:
 current=next(x for x in refs if x['id']==own['id'])
 assert current['baseImageRepoPath']==own['baseImageRepoPath']
 assert s['runId'] in current['baseImageRepoPath'] or current['id']==s['secureReference']['id']
 request('DELETE','/v2/baseimages/'+own['id'],admin=True,timeout=30)
integration=next(x for x in request('GET','/v1/imageintegrations',admin=True)['integrations'] if x['id']==s['secureIntegration']['id'])
assert integration['name']==s['secureIntegration']['name'] and s['runId'] in integration['name']
request('DELETE','/v1/imageintegrations/'+integration['id'],admin=True,timeout=30)
after=request('GET','/v2/baseimages',admin=True)
(W/'references-after-cleanup.json').write_text(json.dumps(after,indent=2))
prior=json.loads((W/'references-before.json').read_text())
assert after==prior,'Original base image references changed'
assert sorted(deployments(),key=lambda x:x['uid'])==sorted(original,key=lambda x:x['uid'])
assert not kub('get','namespace',s['testNamespace'],'--ignore-not-found','-o','name').strip()
s['cleanup']={'at':now(),'testNamespaceRemoved':True,'testReferencesRemoved':[r['id'] for r in to_delete],'testIntegrationRemoved':integration['id'],'originalReferencesUnchanged':True,'originalDeploymentsUnchanged':True,'retained':'Evidence files and test image blobs in existing registry/node/host caches; no registry garbage collection performed.'}
save();print('CLEANUP PASS: test namespace, references and integration removed; original configuration unchanged',flush=True)
