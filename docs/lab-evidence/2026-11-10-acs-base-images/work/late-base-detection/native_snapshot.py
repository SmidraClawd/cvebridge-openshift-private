import sys,json,pathlib,urllib.parse,datetime
sys.path.insert(0,'/home/wing/Documents/Codex/2026-10-31/new-realtime-voice-chat-6/.local/acs-origin-test')
from acs_api import request
W=pathlib.Path(__file__).resolve().parent;s=json.loads((W/'run.json').read_text());label=sys.argv[1]
x=request('GET','/v1/images',admin=True,timeout=25)
x['images']=[a for a in x.get('images',[]) if s['runId'] in str(a.get('name',''))]
(W/(label+'-native-list.json')).write_text(json.dumps(x,ensure_ascii=False,indent=2))
results=[]
for item in x.get('images',[]):
 detail=request('GET','/v1/images/'+urllib.parse.quote(item['id'],safe=''),admin=True,timeout=25)
 (W/(label+'-native-'+item['id'].replace(':','_')+'.json')).write_text(json.dumps(detail,ensure_ascii=False,indent=2))
 r={'id':detail.get('id'),'idV2':detail.get('idV2'),'name':detail.get('name'),'baseMatches':detail.get('baseImageInfo',[]),'scanTime':detail.get('scan',{}).get('scanTime'),'metadataLayers':detail.get('metadata',{}).get('layerShas',[])};results.append(r)
summary={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'label':label,'images':results};(W/(label+'-native-summary.json')).write_text(json.dumps(summary,ensure_ascii=False,indent=2));print(json.dumps(summary,ensure_ascii=False),flush=True)
