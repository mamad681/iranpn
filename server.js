const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const net=require("net"),dgram=require("dgram"),dns=require("dns"),{WebSocketServer}=require("ws");
const DIR=process.env.DATA_DIR||path.join(__dirname,"data"),FILE=path.join(DIR,"state.json");
fs.mkdirSync(DIR,{recursive:true});
const hash=(p,s)=>crypto.scryptSync(p,s,32).toString("hex");
const rid=()=>crypto.randomBytes(5).toString("hex");
let S;try{S=JSON.parse(fs.readFileSync(FILE,"utf8"))}catch{}
if(!S){const salt=rid(),pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(7).toString("hex");
 console.log("ADMIN LOGIN:",process.env.ADMIN_EMAIL||"admin@panel.com",pw);
 S={v:2,users:[{id:"admin",role:"admin",email:process.env.ADMIN_EMAIL||"admin@panel.com",salt,pass:hash(pw,salt),phone:"",bal:0,on:true}],servers:[],plans:[],tx:[],orders:[],subs:[],log:[],notice:"",set:{card:"",owner:"",site:"VPN Panel",minCharge:10000,psk:crypto.randomBytes(8).toString("hex")}}}
if(S.set&&S.set.relay===undefined)S.set.relay=true;
const save=()=>{fs.writeFileSync(FILE+".tmp",JSON.stringify(S));fs.renameSync(FILE+".tmp",FILE)};
const pub=u=>({id:u.id,role:u.role,email:u.email,phone:u.phone,bal:u.bal,on:u.on});
const view=u=>u.role=="admin"?{...S,users:S.users.map(pub)}:{v:2,users:[pub(u)],servers:S.servers.filter(x=>x.on),plans:S.plans,subs:S.subs.filter(x=>x.rep==u.email),tx:S.tx.filter(x=>x.rep==u.email),orders:S.orders.filter(x=>x.rep==u.email),log:[],notice:S.notice,set:{card:S.set.card,owner:S.set.owner,site:S.set.site,minCharge:S.set.minCharge,psk:S.set.psk}};
const sess=new Map(),fails=new Map();
const log=(u,m)=>{S.log.push({t:new Date().toLocaleString("en-GB"),u:u.email,m});S.log=S.log.slice(-300)};
const left=s=>Math.max(0,Math.ceil((s.exp-Date.now())/864e5));
const cap=s=>s.gb*(s.mult||1);
const active=s=>s.on&&left(s)>0&&s.used<cap(s);
const cfgsOf=v=>v.cfgs||[{tr:v.tr,port:(v.ports||{}).vless||443,path:v.path||(v.tr=="ws"?"/ws":"grpc")},{tr:v.tr=="ws"?"grpc":"ws",port:(v.ports||{}).vless||443,path:v.tr=="ws"?"grpc":"/ws"}];
const vless=(s,v,c)=>{const q=new URLSearchParams({encryption:"none",security:"tls",sni:v.sni,fp:"chrome",type:c.tr});if(c.tr=="ws"){q.set("host",v.sni);q.set("path",c.path||"/ws");q.set("alpn","http/1.1")}else{q.set("serviceName",c.path||"grpc");q.set("mode","gun");q.set("alpn","h2")}return`vless://${s.uuid}@${v.addr}:${c.port}?${q}#${encodeURIComponent(v.name+" | "+c.tr.toUpperCase())}`};
const hostOf=q=>String(q.headers["x-forwarded-host"]||q.headers.host||"").split(",")[0].trim().split(":")[0];
const relayLink=(s,h)=>{const q=new URLSearchParams({encryption:"none",security:"tls",sni:h,fp:"chrome",type:"ws",host:h,path:"/ws/"+s.uuid,alpn:"http/1.1"});return`vless://${s.uuid}@${h}:443?${q}#${encodeURIComponent((S.set.site||"VPN")+" | WS")}`};
const H={"X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Frame-Options":"DENY","Strict-Transport-Security":"max-age=31536000","Content-Security-Policy":"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'"};
const send=(r,c,b,t="application/json",x={})=>{r.writeHead(c,{"Content-Type":t,"Cache-Control":"no-store",...H,...x});r.end(typeof b=="string"||Buffer.isBuffer(b)?b:JSON.stringify(b))};
const body=q=>new Promise(ok=>{let d="";q.on("data",c=>{d+=c;if(d.length>2e6)q.destroy()});q.on("end",()=>{try{ok(JSON.parse(d||"{}"))}catch{ok({})}})});
const server=http.createServer(async(q,r)=>{try{
 const url=new URL(q.url,"http://x"),p=url.pathname,ip=q.headers["x-forwarded-for"]?.split(",")[0]||q.socket.remoteAddress;
 if(q.method=="GET"&&p=="/")return send(r,200,fs.readFileSync(path.join(__dirname,"public/index.html")),"text/html; charset=utf-8");
 if(q.method=="GET"&&p.startsWith("/sub/")){const s=S.subs.find(x=>x.tok==p.slice(5));
  if(!s)return send(r,404,"not found","text/plain");
  if((q.headers.accept||"").includes("text/html"))return send(r,302,"","text/plain",{Location:"/#/sub/"+s.tok});
  const h=hostOf(q),L=[];if(S.set.relay!==false&&h)L.push(relayLink(s,h));S.servers.filter(v=>v.on).forEach(v=>cfgsOf(v).forEach(c=>L.push(vless(s,v,c))));const txt=active(s)?L.join("\n"):"";
  return send(r,200,Buffer.from(txt).toString("base64"),"text/plain",{"subscription-userinfo":`upload=0; download=${Math.round(s.used*1073741824)}; total=${Math.round(cap(s)*1073741824)}; expire=${Math.floor(s.exp/1000)}`,"profile-update-interval":"1","profile-title":"base64:"+Buffer.from(String(S.set.site||"VPN")).toString("base64")})}
 if(q.method=="GET"&&p.startsWith("/ovpn/")){const [,,tok,sid]=p.split("/");const s=S.subs.find(x=>x.tok==tok),v=S.servers.find(x=>x.id==sid&&x.on);
  if(!s||!v||!S.set.ovpn||!active(s))return send(r,404,"not found","text/plain");
  return send(r,200,S.set.ovpn.replace(/\{\{SERVER\}\}/g,v.addr).replace(/\{\{PORT\}\}/g,String(v.ports.ovpn)),"application/x-openvpn-profile",{"Content-Disposition":`attachment; filename="${String(v.name||"vpn").replace(/[^\w.-]/g,"_")}.ovpn"`})}
 if(q.method=="GET"&&p.startsWith("/api/sub/")){const s=S.subs.find(x=>x.tok==p.slice(9));if(!s)return send(r,404,{error:"not found"});
  return send(r,200,{sub:{...s,rep:undefined},servers:S.servers.filter(x=>x.on),plans:S.plans.filter(x=>x.id==s.plan),set:{psk:S.set.psk,site:S.set.site,ovpn:!!S.set.ovpn,relay:S.set.relay!==false}})}
 if(q.method=="POST"&&p=="/api/login"){const b=await body(q),f=fails.get(ip)||{n:0,t:0};
  if(f.t>Date.now())return send(r,429,{error:"Too many attempts, wait 1 min"});
  const u=S.users.find(x=>x.email==String(b.email||"").trim());
  const ok=u&&crypto.timingSafeEqual(Buffer.from(hash(String(b.pass||""),u.salt),"hex"),Buffer.from(u.pass,"hex"));
  if(!ok){f.n++;if(f.n>=5){f.t=Date.now()+6e4;f.n=0}fails.set(ip,f);return send(r,401,{error:"Wrong email or password"})}
  if(!u.on)return send(r,403,{error:"Account disabled"});
  fails.delete(ip);const t=crypto.randomBytes(24).toString("hex");sess.set(t,{id:u.id,exp:Date.now()+36e5});log(u,"login");save();
  return send(r,200,{token:t,uid:u.id,state:view(u)})}
 if(!p.startsWith("/api/"))return send(r,404,"not found","text/plain");
 if(p.startsWith("/api/sync/")){const k=Buffer.from(String(q.headers["x-sync-key"]||"")),sk=Buffer.from(process.env.SYNC_KEY||"");
  if(!sk.length||k.length!=sk.length||!crypto.timingSafeEqual(k,sk))return send(r,403,{error:"Admins only"});
  if(q.method=="GET"&&p=="/api/sync/users")return send(r,200,{users:S.subs.filter(active).map(s=>({id:s.id,uuid:s.uuid,pw:s.pw}))});
  if(q.method=="GET"&&p=="/api/sync/config")return send(r,200,{l2tpPsk:S.set.psk,site:S.set.site||"VPN Panel"});
  if(q.method=="POST"&&p=="/api/sync/usage"){const b=await body(q);let n=0;for(const it of Array.isArray(b.items)?b.items:[]){const s=S.subs.find(x=>x.id==it.id),by=+it.bytes;if(s&&by>0){s.used=+(s.used+by/1073741824).toFixed(4);n++}}save();return send(r,200,{ok:1,n})}
  return send(r,404,{error:"not found"})}
 const ss=sess.get((q.headers.authorization||"").slice(7)),u=ss&&ss.exp>Date.now()&&S.users.find(x=>x.id==ss.id&&x.on);
 if(!u)return send(r,401,{error:"Please log in"});ss.exp=Date.now()+36e5;
 const adm=u.role=="admin",b=q.method=="GET"?{}:await body(q);
 if(q.method=="GET"&&p=="/api/state")return send(r,200,view(u));
 if(p=="/api/pass"&&String(b.pass||"").length>=8){u.salt=rid();u.pass=hash(b.pass,u.salt);log(u,"password changed");save();return send(r,200,{ok:1})}
 if(p=="/api/buy"){const pl=S.plans.find(x=>x.id==b.plan);if(!pl)return send(r,400,{error:"Plan not found"});if(u.bal<pl.whole)return send(r,400,{error:"Not enough balance"});
  u.bal-=pl.whole;S.subs.push({id:rid(),tok:crypto.randomBytes(12).toString("hex"),uuid:crypto.randomUUID(),pw:rid(),rep:u.email,name:String(b.name||"").slice(0,40)||"me",plan:pl.id,gb:pl.gb,mult:pl.mult||1,used:0,users:pl.users||1,exp:Date.now()+pl.days*864e5,on:true});
  S.orders.push({rep:u.email,plan:pl.id,price:pl.whole});log(u,"buy "+pl.name);save();return send(r,200,{ok:1})}
 if(p=="/api/charge"){const a=+b.amount;if(!(a>=S.set.minCharge))return send(r,400,{error:"Below minimum"});S.tx.push({id:rid(),type:"charge",rep:u.email,amount:a,ref:String(b.ref||"").slice(0,40),status:"pending"});save();return send(r,200,{ok:1})}
 if(!adm)return send(r,403,{error:"Admins only"});
 if(p=="/api/rep"){if(S.users.some(x=>x.email==b.email)||String(b.pass||"").length<8||!b.email)return send(r,400,{error:"Invalid or duplicate"});
  const salt=rid();S.users.push({id:rid(),role:"rep",email:String(b.email).trim(),salt,pass:hash(b.pass,salt),phone:String(b.phone||""),bal:+b.bal||0,on:true});log(u,"add reseller "+b.email);save();return send(r,200,{ok:1})}
 if(p=="/api/usage"){const x=S.subs.find(y=>y.id==b.id),g=+b.gb;if(!x||!isFinite(g))return send(r,400,{error:"Invalid"});x.used=Math.max(0,+(x.used+g).toFixed(4));log(u,"usage "+g+" "+x.name);save();return send(r,200,{ok:1,used:x.used})}
 if(q.method=="PUT"&&p=="/api/state"){if(!["servers","plans","tx","orders","subs"].every(k=>Array.isArray(b[k]))||!b.set)return send(r,400,{error:"Bad state"});
  b.users?.forEach(c=>{const x=S.users.find(y=>y.id==c.id);if(x&&x.role=="rep"){x.bal=+c.bal||0;x.on=!!c.on;x.phone=String(c.phone||"")}});
  b.subs.forEach(n=>{const o=S.subs.find(y=>y.id==n.id);if(o)n.used=o.used});Object.assign(S,{servers:b.servers,plans:b.plans,tx:b.tx,orders:b.orders,subs:b.subs,notice:String(b.notice||""),set:b.set});save();return send(r,200,{ok:1})}
 send(r,404,{error:"not found"})}catch(e){console.error(e);send(r,500,{error:"server error"})}}).listen(process.env.PORT||3000,()=>console.log("up"));

// ===== Built-in VLESS-over-WebSocket relay =====
// Users are authenticated instantly from the panel state (no 60s sync, no Xray restart),
// so the client's delay test (ping) works right after purchase. Path: /ws/<uuid>
const ALLOW_PRIV=process.env.RELAY_ALLOW_PRIVATE=="1"; // test only
const norm6=ip=>{try{return new URL("http://["+ip+"]").hostname.slice(1,-1)}catch{return ip}};
const isPriv=ip=>{if(net.isIPv6(ip)){ip=norm6(ip);let m=ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if(m){const x=parseInt(m[1],16),y=parseInt(m[2],16);ip=[x>>8,x&255,y>>8,y&255].join(".")}else{m=ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);if(m)ip=m[1]}}
 if(net.isIPv4(ip)){const[a,b]=ip.split(".").map(Number);return a==0||a==10||a==127||a>=224||(a==100&&b>=64&&b<=127)||(a==169&&b==254)||(a==172&&b>=16&&b<=31)||(a==192&&b==168)||(a==192&&b==0)||(a==198&&(b==18||b==19))}
 return ip=="::"||ip=="::1"||/^f[cd]/.test(ip)||/^fe[89ab]/.test(ip)||/^ff/.test(ip)};
const resolve=(h,cb)=>{if(net.isIP(h))return cb(null,h);dns.lookup(h,{family:4},(e,a)=>e?dns.lookup(h,{family:6},(e2,a2)=>cb(e2,a2)):cb(null,a))};
const parse=b=>{try{if(b.length<24||b[0]!==0)return null;const uid=b.subarray(1,17).toString("hex");let p=18+b[17];const cmd=b[p++],port=b.readUInt16BE(p);p+=2;const t=b[p++];let addr;
 if(t==1){addr=[...b.subarray(p,p+4)].join(".");p+=4}else if(t==2){const l=b[p++];addr=b.subarray(p,p+l).toString();p+=l}else if(t==3){const a=[];for(let i=0;i<8;i++)a.push(b.readUInt16BE(p+i*2).toString(16));addr=a.join(":");p+=16}else return null;
 return{uid,cmd,port,addr,rest:b.subarray(p)}}catch{return null}};
const live=new Map(),pend=new Map();
const flush=()=>{let ch=false;
 for(const[id,n]of pend){const s=S.subs.find(x=>x.id==id);if(s){s.used+=n/1073741824;ch=true}}pend.clear();
 for(const[id,set]of live){const s=S.subs.find(x=>x.id==id);if(!s||!active(s))for(const c of[...set])c.kill()}
 if(ch)save()};
setInterval(flush,1500);
for(const sg of["SIGTERM","SIGINT"])process.on(sg,()=>{try{flush()}catch{}process.exit(0)});
process.on("uncaughtException",e=>console.error("uncaught",e));
process.on("unhandledRejection",e=>console.error("unhandled",e));
const wss=new WebSocketServer({noServer:true,perMessageDeflate:false,maxPayload:8<<20});
server.on("upgrade",(q,sock,head)=>{sock.on("error",()=>{});
 let s=null;try{const m=/^\/ws\/([0-9a-f-]{36})$/i.exec(new URL(q.url,"http://x").pathname);s=m&&S.set.relay!==false&&S.subs.find(x=>x.uuid==m[1].toLowerCase())}catch{}
 if(!s||!active(s)){sock.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");return}
 wss.handleUpgrade(q,sock,head,ws=>relay(ws,s))});
function relay(ws,s){
 const id=s.id,want=s.uuid.replace(/-/g,"").toLowerCase();
 let tcp=null,udp=null,sent=false,dead=false,got=false,ready=null,alive=true,hb=null;const pre=[];
 const add=n=>pend.set(id,(pend.get(id)||0)+n);
 const c={kill(){try{ws.close(1008,"quota")}catch{}setTimeout(end,300)}};
 const end=()=>{if(dead)return;dead=true;clearInterval(hb);const l=live.get(id);if(l){l.delete(c);if(!l.size)live.delete(id)}try{tcp&&tcp.destroy()}catch{}try{udp&&udp.close()}catch{}try{ws.terminate()}catch{}};
 const finish=()=>{if(dead)return;try{ws.close()}catch{}setTimeout(end,3000)};
 (live.get(id)||live.set(id,new Set()).get(id)).add(c);
 ws.on("pong",()=>{alive=true});
 hb=setInterval(()=>{if(!alive)return end();alive=false;try{ws.ping()}catch{}},25000);
 const out=d=>{if(dead||ws.readyState!==1)return;add(d.length);const b=sent?d:Buffer.concat([Buffer.from([0,0]),d]);sent=true;
  ws.send(b,{binary:true},e=>{if(!e&&tcp&&ws.bufferedAmount<(1<<20))tcp.resume()});if(tcp&&ws.bufferedAmount>(2<<20))tcp.pause()};
 const startTcp=(ip,port,rest)=>{tcp=net.connect({host:ip,port});tcp.setNoDelay(true);
  tcp.setTimeout(15000,()=>{if(tcp.connecting)finish()});
  tcp.on("data",out);tcp.on("error",finish);tcp.on("close",finish);
  ready=d=>{add(d.length);if(!tcp.write(d)){ws.pause();tcp.once("drain",()=>ws.resume())}};
  if(rest.length)ready(rest);pre.splice(0).forEach(ready)};
 const startUdp=(ip,port,rest)=>{udp=dgram.createSocket(net.isIPv6(ip)?"udp6":"udp4");udp.on("error",finish);
  udp.on("message",m=>{const f=Buffer.allocUnsafe(2+m.length);f.writeUInt16BE(m.length);m.copy(f,2);out(f)});
  let rem=Buffer.alloc(0);
  ready=d=>{rem=rem.length?Buffer.concat([rem,d]):d;let p=0;while(rem.length-p>=2){const l=rem.readUInt16BE(p);if(rem.length-p-2<l)break;const pk=rem.subarray(p+2,p+2+l);p+=2+l;add(pk.length);udp.send(pk,port,ip)}rem=rem.subarray(p)};
  if(rest.length)ready(rest);pre.splice(0).forEach(ready)};
 ws.on("error",end);ws.on("close",end);
 ws.on("message",data=>{if(dead)return;
  const b=Array.isArray(data)?Buffer.concat(data):Buffer.isBuffer(data)?data:Buffer.from(data);
  if(got){if(ready)ready(b);else pre.push(b);return}
  got=true;const h=parse(b);
  if(!h||h.uid!==want||(h.cmd!=1&&h.cmd!=2))return end();
  resolve(h.addr,(e,ip)=>{if(dead)return;if(e||!ip||(!ALLOW_PRIV&&isPriv(ip)))return end();h.cmd==1?startTcp(ip,h.port,h.rest):startUdp(ip,h.port,h.rest)})});
 setTimeout(()=>{if(!got)end()},15000);
}
