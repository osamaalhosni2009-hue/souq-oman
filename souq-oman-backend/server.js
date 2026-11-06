"use strict";
// Souq Oman backend — zero dependencies (Node 18+).  Run: ADMIN_PASSWORD='long-secret' node server.js
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const PORT=+process.env.PORT||3000,PASS=process.env.ADMIN_PASSWORD||"";
const ORIGINS=(process.env.ALLOWED_ORIGINS||"").split(",").map(s=>s.trim()).filter(Boolean);
if(PASS.length<8){console.error("Set ADMIN_PASSWORD (8+ chars). Example: ADMIN_PASSWORD='change-me-now' node server.js");process.exit(1)}
const D=path.join(__dirname,"data"),UP=path.join(D,"uploads"),DBF=path.join(D,"db.json"),LOG=path.join(D,"audit.log");
fs.mkdirSync(UP,{recursive:true});
let db={items:[]};try{db=JSON.parse(fs.readFileSync(DBF,"utf8"))}catch(e){}
const save=()=>{fs.writeFileSync(DBF+".tmp",JSON.stringify(db));fs.renameSync(DBF+".tmp",DBF)};
const rid=()=>crypto.randomBytes(6).toString("hex");
const ip=r=>(process.env.TRUST_PROXY&&String(r.headers["x-forwarded-for"]||"").split(",")[0].trim())||r.socket.remoteAddress;
const audit=(r,action,d={})=>fs.appendFile(LOG,JSON.stringify({ts:new Date().toISOString(),ip:ip(r),action,...d})+"\n",()=>{});
const E=(status,message)=>Object.assign(new Error(message),{status});
const CATS={electronics:"📱",gaming:"🎮",cars:"🚗",property:"🏠",fashion:"👗",home:"🛋️",jobs:"💼",services:"🛠️",pets:"🐾"};
const CITIES=["muscat","salalah","sohar","nizwa","sur","rustaq","buraimi"];
const V={ig:s=>/^[A-Za-z0-9._]{1,30}$/.test(s||"")?s:"",wa:s=>/^\d{8,15}$/.test(s||"")?s:"",web:s=>{try{const u=new URL(s);return/^https?:$/.test(u.protocol)?u.href.slice(0,200):""}catch(e){return""}}};
const str=(s,n)=>String(s==null?"":s).replace(/[\u0000-\u001f<>]/g,"").trim().slice(0,n);
const hits=new Map();
const limited=(k,max,win)=>{const n=Date.now(),h=hits.get(k);if(!h||h.r<n){hits.set(k,{c:1,r:n+win});return false}return++h.c>max};
setInterval(()=>{const n=Date.now();for(const[k,h]of hits)if(h.r<n)hits.delete(k)},6e4).unref();
const sess=new Map(),sha=s=>crypto.createHash("sha256").update(s).digest();
const authed=r=>{const t=(r.headers.authorization||"").slice(7),e=sess.get(t);if(e&&e>Date.now())return true;sess.delete(t);return false};
function saveImg(d){
 const m=/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(d||"");if(!m)return "";
 const b=Buffer.from(m[2],"base64"),h=b.subarray(0,4).toString("hex");
 if(b.length>4e5)throw E(413,"image too large");
 const okMagic=(m[1]=="jpeg"&&h.startsWith("ffd8ff"))||(m[1]=="png"&&h=="89504e47")||(m[1]=="webp"&&b.subarray(0,4).toString()=="RIFF");
 if(!okMagic)throw E(400,"bad image");
 const n=rid()+rid()+"."+(m[1]=="jpeg"?"jpg":m[1]);fs.writeFileSync(path.join(UP,n),b);return "/uploads/"+n;
}
function build(b){
 const type=b.type=="shop"?"shop":"ad",cat=CATS[b.cat]?b.cat:"";
 const it={id:rid(),type,status:"pending",ts:Date.now(),cat,e:CATS[cat]||"🛍️",ig:V.ig(str(b.ig,30)),web:V.web(str(b.web,200)),wa:V.wa(str(b.wa,15))};
 if(type=="shop"){it.n=str(b.n,60);it.tags=(Array.isArray(b.tags)?b.tags:[]).slice(0,6).map(x=>str(x,24)).filter(Boolean);if(it.n.length<2||!it.ig)throw E(400,"invalid shop")}
 else{it.t=str(b.t,80);it.p=Math.round(Number(b.p)*1000)/1000;it.city=CITIES.includes(b.city)?b.city:"muscat";it.store=b.store?1:0;
  if(it.t.length<3||!(it.p>=0&&it.p<1e8))throw E(400,"invalid ad");
  if(!it.ig&&!it.web&&!it.wa)throw E(400,"contact required");
  it.img=b.img?saveImg(b.img):""}
 return it;
}
const pub=i=>i.type=="ad"?{id:i.id,cat:i.cat,city:i.city,t:i.t,p:i.p,img:i.img,ig:i.ig,web:i.web,wa:i.wa,store:i.store,e:i.e,ts:i.ts,h:25}:{id:i.id,n:i.n,ig:i.ig,web:i.web,wa:i.wa,cat:i.cat,e:i.e,tags:i.tags};
const body=(req,max=7e5)=>new Promise((ok,no)=>{let n=0;const c=[];req.on("data",d=>{n+=d.length;if(n>max){no(E(413,"too large"));req.destroy();return}c.push(d)});req.on("end",()=>{try{ok(JSON.parse(Buffer.concat(c).toString()||"{}"))}catch(e){no(E(400,"bad json"))}});req.on("error",no)});
const MIME={html:"text/html; charset=utf-8",jpg:"image/jpeg",png:"image/png",webp:"image/webp"};
function file(res,rel,extra={}){fs.readFile(path.join(__dirname,rel),(e,b)=>{if(e){res.writeHead(404).end();return}res.writeHead(200,{"Content-Type":MIME[rel.split(".").pop()],...extra});res.end(b)})}
const tail=()=>{if(!fs.existsSync(LOG))return[];const st=fs.statSync(LOG).size,n=Math.min(st,3e5),fd=fs.openSync(LOG,"r"),b=Buffer.alloc(n);fs.readSync(fd,b,0,n,st-n);fs.closeSync(fd);
 return b.toString("utf8").split("\n").filter(Boolean).slice(-200).reverse().map(l=>{try{return JSON.parse(l)}catch(e){return null}}).filter(Boolean)};

http.createServer(async(req,res)=>{
 const o=req.headers.origin;
 if(o&&ORIGINS.includes(o)){res.setHeader("Access-Control-Allow-Origin",o);res.setHeader("Vary","Origin");res.setHeader("Access-Control-Allow-Headers","Content-Type,Authorization");res.setHeader("Access-Control-Allow-Methods","GET,POST,DELETE,OPTIONS")}
 res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("Referrer-Policy","no-referrer");
 if(req.method=="OPTIONS"){res.writeHead(204).end();return}
 const u=new URL(req.url,"http://x"),p=u.pathname,m=req.method;
 const send=(c,x)=>{res.writeHead(c,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"});res.end(JSON.stringify(x))};
 try{
  if(m=="GET"&&(p=="/"||p=="/index.html"))return file(res,"public/index.html");
  if(m=="GET"&&(p=="/admin"||p=="/admin/"))return file(res,"admin/index.html",{"X-Frame-Options":"DENY","X-Robots-Tag":"noindex"});
  const up=/^\/uploads\/([a-f0-9]{24}\.(jpg|png|webp))$/.exec(p);
  if(m=="GET"&&up)return file(res,"data/uploads/"+up[1],{"Cache-Control":"public,max-age=86400"});
  if(m=="GET"&&p=="/api/health")return send(200,{ok:true});
  if(m=="GET"&&(p=="/api/ads"||p=="/api/shops")){const t=p=="/api/ads"?"ad":"shop";return send(200,{items:db.items.filter(i=>i.type==t&&i.status=="approved").sort((a,b)=>b.ts-a.ts).map(pub)})}
  if(m=="POST"&&p=="/api/requests"){
   if(limited("req:"+ip(req),10,36e5))throw E(429,"too many requests");
   const it=build(await body(req));db.items.push(it);save();audit(req,"submit",{id:it.id,type:it.type});return send(201,{id:it.id});
  }
  if(m=="POST"&&p=="/api/admin/login"){
   if(limited("login:"+ip(req),8,9e5)){audit(req,"login_blocked");throw E(429,"too many attempts")}
   const b=await body(req,2e3);
   if(!crypto.timingSafeEqual(sha(String(b.password||"")),sha(PASS))){audit(req,"login_fail");throw E(401,"wrong password")}
   const t=crypto.randomBytes(24).toString("hex");sess.set(t,Date.now()+432e5);audit(req,"login_ok");return send(200,{token:t});
  }
  if(p.startsWith("/api/admin/")){
   if(!authed(req))throw E(401,"unauthorized");
   if(m=="GET"&&p=="/api/admin/requests"){const s=u.searchParams.get("status")||"pending";return send(200,{items:db.items.filter(i=>i.status==s).sort((a,b)=>b.ts-a.ts)})}
   if(m=="GET"&&p=="/api/admin/stats"){const c=(s,t)=>db.items.filter(i=>i.status==s&&(!t||i.type==t)).length;return send(200,{pending:c("pending"),pendingAds:c("pending","ad"),pendingShops:c("pending","shop"),approved:c("approved"),rejected:c("rejected")})}
   if(m=="GET"&&p=="/api/admin/logs")return send(200,{items:tail()});
   if(m=="POST"&&p=="/api/admin/shops"){const b=await body(req);const it=build({...b,type:"shop"});it.status="approved";it.source="admin";it.reviewedAt=Date.now();db.items.push(it);save();audit(req,"admin_add_shop",{id:it.id,n:it.n});return send(201,{id:it.id})}
   const a=/^\/api\/admin\/items\/([a-f0-9]{12})\/(approve|reject)$/.exec(p);
   if(m=="POST"&&a){
    const it=db.items.find(i=>i.id==a[1]);if(!it)throw E(404,"not found");
    const b=await body(req,5e3);it.status=a[2]=="approve"?"approved":"rejected";it.reviewedAt=Date.now();if(a[2]=="reject")it.reason=str(b.reason,200);
    save();audit(req,a[2],{id:it.id,type:it.type});return send(200,{ok:true});
   }
   const d=/^\/api\/admin\/items\/([a-f0-9]{12})$/.exec(p);
   if(m=="DELETE"&&d){
    const i=db.items.findIndex(x=>x.id==d[1]);if(i<0)throw E(404,"not found");
    const it=db.items.splice(i,1)[0];if(it.img)fs.unlink(path.join(D,it.img.replace("/uploads/","uploads/")),()=>{});
    save();audit(req,"delete",{id:it.id,type:it.type});return send(200,{ok:true});
   }
  }
  send(404,{error:"not found"});
 }catch(e){send(e.status||500,{error:e.status?e.message:"server error"});if(!e.status)console.error(e)}
}).listen(PORT,()=>console.log("Souq Oman running: user site http://localhost:"+PORT+"  admin http://localhost:"+PORT+"/admin"));
