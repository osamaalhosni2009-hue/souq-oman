"use strict";
// Souq Oman backend — zero dependencies (Node 18+).  Run: ADMIN_PASSWORD='long-secret' node server.js
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
// Settings file: edit config.env (or .env) next to this file. Real environment variables win over the file.
for(const f of ["config.env",".env"]){try{for(const l of fs.readFileSync(path.join(__dirname,f),"utf8").split(/\r?\n/)){const m=/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(l);if(m&&!l.trim().startsWith("#")&&process.env[m[1]]===undefined)process.env[m[1]]=m[2].replace(/^["']|["']$/g,"")}}catch(e){}}
const PORT=+process.env.PORT||3000,PASS=process.env.ADMIN_PASSWORD||"";
const ORIGINS=(process.env.ALLOWED_ORIGINS||"").split(",").map(s=>s.trim()).filter(Boolean);
if(PASS&&PASS.length<8){console.error("ADMIN_PASSWORD must be 8+ chars (or leave it unset).");process.exit(1)}
const D=path.join(__dirname,"data"),UP=path.join(D,"uploads"),DBF=path.join(D,"db.json"),LOG=path.join(D,"audit.log");
fs.mkdirSync(UP,{recursive:true});
let db={items:[]};try{db=JSON.parse(fs.readFileSync(DBF,"utf8"))}catch(e){}
if(!db.ratings)db.ratings=[];
if(!Array.isArray(db.aiPayments))db.aiPayments=[];
if(!db.aiSubscriptions)db.aiSubscriptions={};
const save=()=>{fs.writeFileSync(DBF+".tmp",JSON.stringify(db));fs.renameSync(DBF+".tmp",DBF)};
if(!db.secret){db.secret=crypto.randomBytes(32).toString("hex");save()}
const rid=()=>crypto.randomBytes(6).toString("hex");
const ip=r=>(process.env.TRUST_PROXY&&String(r.headers["x-forwarded-for"]||"").split(",")[0].trim())||r.socket.remoteAddress;
const audit=(r,action,d={})=>fs.appendFile(LOG,JSON.stringify({ts:new Date().toISOString(),ip:ip(r),action,...d})+"\n",()=>{});
const E=(status,message)=>Object.assign(new Error(message),{status});
const CATS={web:"🌐",apps:"📱",software:"💻",support:"🛠️",network:"📡",security:"🔐",ai:"🤖",design:"🎨",cloud:"☁️"};
const CITIES=["muscat","salalah","sohar","nizwa","sur","rustaq","buraimi"];
const V={ig:s=>/^[A-Za-z0-9._]{1,30}$/.test(s||"")?s:"",wa:s=>/^\d{8,15}$/.test(s||"")?s:"",web:s=>{try{const u=new URL(s);return/^https?:$/.test(u.protocol)?u.href.slice(0,200):""}catch(e){return""}}};
const str=(s,n)=>String(s==null?"":s).replace(/[\u0000-\u001f<>]/g,"").trim().slice(0,n);
V.url=s=>{try{const u=new URL(s);return/^https?:$/.test(u.protocol)?u.href.slice(0,400):""}catch(e){return""}};
const prods=a=>(Array.isArray(a)?a:[]).slice(0,300).map(x=>({t:str(x&&x.t,120),p:Math.max(0,Math.round(Number(x&&x.p)*1000)/1000)||0,u:V.url(x&&x.u)})).filter(x=>x.t.length>1);
// Seed stores (seed/shops.json): applied once per seed version; products are merged by title.
try{const sd=JSON.parse(fs.readFileSync(path.join(__dirname,"seed","shops.json"),"utf8"));
 if((db.seedV||0)<sd.version){const validSeedIds=new Set(sd.items.map(s=>crypto.createHash("sha1").update("seed:"+(s.ig||s.web||s.n)).digest("hex").slice(0,12)));db.items=db.items.filter(i=>i.source!=="seed"||validSeedIds.has(i.id));for(const s of sd.items){const id=crypto.createHash("sha1").update("seed:"+(s.ig||s.web||s.n)).digest("hex").slice(0,12);
  const pr=prods(s.products),ex=db.items.find(i=>i.id==id),cat=CATS[s.cat]?s.cat:"",city=CITIES.includes(s.city)?s.city:"",tags=(s.tags||[]).map(x=>str(x,40));
  if(ex){const have=new Set((ex.products||[]).map(x=>x.t));ex.products=[...(ex.products||[]),...pr.filter(x=>!have.has(x.t))].slice(0,300);if(ex.source=="seed"){ex.cat=cat;ex.e=s.e||CATS[cat]||"🛍️";ex.city=city;ex.tags=tags;ex.logo=V.url(s.logo)}}
  else db.items.push({id,type:"shop",status:"approved",source:"seed",ts:Date.now(),cat,e:s.e||CATS[cat]||"🛍️",n:str(s.n,60),ig:V.ig(s.ig),web:V.web(s.web),wa:V.wa(s.wa),city,tags,logo:V.url(s.logo),products:pr})}
 db.seedV=sd.version;save()}}catch(e){console.error("seed:",e.message)}
const CTL_IDS=["post","lang","hero","search","academy","sugg","cities","cats","shops","latest","footer","rating","userdel","login"];
const TXT_KEYS=["brand","post","rbtn","h1","sub","go","ph","latest","shops","foot"];
const cleanSettings=b=>{const st={hidden:[],text:{ar:{},en:{}},requireLogin:false,sort:"rating",catOrder:[]};b=b||{};
 if(Array.isArray(b.hidden))st.hidden=b.hidden.filter(x=>CTL_IDS.includes(x)||(/^cat_/.test(x)&&CATS[x.slice(4)]));
 st.requireLogin=!!b.requireLogin;st.sort=["rating","new","name"].includes(b.sort)?b.sort:"rating";
 if(Array.isArray(b.catOrder))st.catOrder=[...new Set(b.catOrder.filter(x=>CATS[x]))];
 for(const l of["ar","en"])for(const k of TXT_KEYS){const v=str(b.text&&b.text[l]&&b.text[l][k],160);if(v)st.text[l][k]=v}return st};
// ---- Google sign-in (ID token verified locally against Google public keys) + stateless user sessions ----
const GID=process.env.GOOGLE_CLIENT_ID||"",JWKS_URL=process.env.GOOGLE_JWKS_URL||"https://www.googleapis.com/oauth2/v3/certs";
let jwks={keys:[],t:0};
const b64u=s=>Buffer.from(String(s).replace(/-/g,"+").replace(/_/g,"/"),"base64");
async function googleVerify(tok){
 const [h,p,s]=String(tok||"").split(".");if(!h||!p||!s)throw E(401,"bad token");
 let head,pl;try{head=JSON.parse(b64u(h).toString());pl=JSON.parse(b64u(p).toString())}catch(e){throw E(401,"bad token")}
 if(head.alg!=="RS256")throw E(401,"bad alg");
 const find=()=>jwks.keys.find(k=>k.kid==head.kid);
 if(!find()||Date.now()-jwks.t>36e5){try{const r=await fetch(JWKS_URL);if(r.ok)jwks={keys:(await r.json()).keys||[],t:Date.now()}}catch(e){}}
 const jwk=find();if(!jwk)throw E(401,"unknown key");
 let ok=false;try{ok=crypto.verify("RSA-SHA256",Buffer.from(h+"."+p),crypto.createPublicKey({key:jwk,format:"jwk"}),b64u(s))}catch(e){}
 if(!ok||!["https://accounts.google.com","accounts.google.com"].includes(pl.iss)||pl.aud!==GID||!(pl.exp*1000>Date.now())||!pl.sub||!pl.email||pl.email_verified!==true)throw E(401,"invalid or unverified Google account");
 return pl;
}
const hmac=b=>crypto.createHmac("sha256",db.secret).update(b).digest("base64url");
const mkUser=pl=>{const b=Buffer.from(JSON.stringify({sub:String(pl.sub),n:str(pl.name||pl.email,60),email:str(pl.email,254),v:pl.email_verified===true,pic:String(pl.picture||"").slice(0,300),exp:Date.now()+2592e6})).toString("base64url");return "u."+b+"."+hmac(b)};
const userOf=r=>{const t=(r.headers.authorization||"").slice(7);if(!t.startsWith("u."))return null;const [,b,s]=t.split(".");if(!b||!s)return null;const g=hmac(b);if(g.length!==s.length||!crypto.timingSafeEqual(Buffer.from(g),Buffer.from(s)))return null;try{const o=JSON.parse(Buffer.from(b,"base64url").toString());return o.exp>Date.now()?o:null}catch(e){return null}};
const off=id=>cleanSettings(db.settings).hidden.includes(id);
const dropItem=it=>{const i=db.items.indexOf(it);if(i>=0)db.items.splice(i,1);if(it.img)fs.unlink(path.join(D,it.img.replace("/uploads/","uploads/")),()=>{})};
const hits=new Map();
const limited=(k,max,win)=>{const n=Date.now(),h=hits.get(k);if(!h||h.r<n){hits.set(k,{c:1,r:n+win});return false}return++h.c>max};
setInterval(()=>{const n=Date.now();for(const[k,h]of hits)if(h.r<n)hits.delete(k)},6e4).unref();
const sess=new Map(),sha=s=>crypto.createHash("sha256").update(s).digest();
// Login code: ADMIN_PASSWORD (if set) always works as a master/recovery code. Until a new code is set from the admin panel, TARIQ123 also works.
const DEFAULT_CODE="TARIQ123";
const eqs=(a,b)=>crypto.timingSafeEqual(sha(String(a||"")),sha(String(b||"")));
function checkCode(c){c=String(c||"");
 if(PASS&&eqs(c,PASS))return true;
 if(db.admin&&db.admin.hash){try{return crypto.timingSafeEqual(crypto.scryptSync(c,Buffer.from(db.admin.salt,"hex"),32),Buffer.from(db.admin.hash,"hex"))}catch(e){return false}}
 return eqs(c,DEFAULT_CODE)}
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
 if(type=="shop"){it.n=str(b.n,60);it.tags=(Array.isArray(b.tags)?b.tags:[]).slice(0,6).map(x=>str(x,40)).filter(Boolean);it.city=CITIES.includes(b.city)?b.city:"";it.logo=V.url(str(b.logo,400));if(it.n.length<2||(!it.ig&&!it.web&&!it.wa))throw E(400,"invalid shop")}
 else{it.t=str(b.t,80);it.p=Math.round(Number(b.p)*1000)/1000;it.city=CITIES.includes(b.city)?b.city:"muscat";it.store=b.store?1:0;
  if(it.t.length<3||!(it.p>=0&&it.p<1e8))throw E(400,"invalid ad");
  if(!it.ig&&!it.web&&!it.wa)throw E(400,"contact required");
  it.img=b.img?saveImg(b.img):""}
 return it;
}
const pub=i=>i.type=="ad"?{id:i.id,cat:i.cat,city:i.city,t:i.t,p:i.p,img:i.img,ig:i.ig,web:i.web,wa:i.wa,store:i.store,e:i.e,ts:i.ts,h:25}:{id:i.id,n:i.n,ig:i.ig,web:i.web,wa:i.wa,cat:i.cat,city:i.city,e:i.e,tags:i.tags,logo:i.logo||"",products:i.products||[]};
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
  if(m=="GET"&&(p=="/academy"||p=="/academy/"))return file(res,"public/academy.html");
  if(m=="GET"&&(p=="/admin"||p=="/admin/"))return file(res,"admin/index.html",{"X-Frame-Options":"DENY","X-Robots-Tag":"noindex"});
  const up=/^\/uploads\/([a-f0-9]{24}\.(jpg|png|webp))$/.exec(p);
  if(m=="GET"&&up)return file(res,"data/uploads/"+up[1],{"Cache-Control":"public,max-age=86400"});
  if(m=="GET"&&p=="/api/health")return send(200,{ok:true});
  if(m=="GET"&&p=="/api/settings")return send(200,{...cleanSettings(db.settings),google:GID});
  if(m=="GET"&&(p=="/api/ads"||p=="/api/shops")){const t=p=="/api/ads"?"ad":"shop";return send(200,{items:db.items.filter(i=>i.type==t&&i.status=="approved").sort((a,b)=>b.ts-a.ts).map(pub)})}
  if(m=="POST"&&p=="/api/auth/google"){
   if(!GID)throw E(503,"google login not configured");
   if(limited("gl:"+ip(req),30,36e5))throw E(429,"too many requests");
   const pl=await googleVerify((await body(req,6e3)).credential);audit(req,"login_google",{u:String(pl.sub).slice(-6)});
   return send(200,{token:mkUser(pl),user:{name:pl.name||"",email:pl.email||"",pic:pl.picture||"",verified:true}});
  }
  if(m=="GET"&&p=="/api/me"){const u=userOf(req);if(!u)throw E(401,"login required");return send(200,{name:u.n,pic:u.pic})}
  if(m=="GET"&&p=="/api/me/ads"){const u=userOf(req);if(!u)throw E(401,"login required");return send(200,{items:db.items.filter(i=>i.type=="ad"&&i.owner==u.sub).sort((a,b)=>b.ts-a.ts).map(i=>({id:i.id,t:i.t,p:i.p,status:i.status,ts:i.ts,city:i.city}))})}
  if(m=="GET"&&p=="/api/ratings")return send(200,{items:db.ratings.slice(-2000).map(r=>({id:r.id,shop:r.shop,stars:r.stars,text:r.text,ts:r.ts}))});
  if(m=="POST"&&p=="/api/ratings"){
   if(off("rating"))throw E(403,"ratings disabled");
   const u=userOf(req);if(cleanSettings(db.settings).requireLogin&&!u)throw E(401,"login required");
   if(limited("rt:"+ip(req),20,36e5))throw E(429,"too many requests");
   const b=await body(req,4e3),shop=db.items.find(x=>x.id==String(b.shop)&&x.type=="shop"&&x.status=="approved"),stars=Math.round(Number(b.stars)),did=str(b.did,40);
   if(!shop||!(stars>=1&&stars<=5)||did.length<8)throw E(400,"invalid rating");
   const k=sha("rt:"+(u?"u"+u.sub:did)+":"+shop.id).toString("hex").slice(0,16);let r=db.ratings.find(x=>x.k==k);if(!r){r={id:rid(),k,shop:shop.id};db.ratings.push(r)}
   r.stars=stars;r.text=str(b.text,200);r.ts=Date.now();save();audit(req,"rate",{id:r.id,shop:shop.id,stars});return send(200,{ok:true});
  }
  const ud=/^\/api\/ads\/([a-f0-9]{12})\/delete$/.exec(p);
  if(m=="POST"&&ud){
   if(off("userdel"))throw E(403,"disabled");
   if(limited("ud:"+ip(req),20,36e5))throw E(429,"too many requests");
   const b=await body(req,2e3),it=db.items.find(x=>x.id==ud[1]&&x.type=="ad");
   const u=userOf(req),okTok=it&&it.tokHash&&b.token&&crypto.timingSafeEqual(sha(String(b.token)),Buffer.from(it.tokHash,"hex"));
   if(!it||!(okTok||(u&&it.owner&&it.owner==u.sub)))throw E(403,"not allowed");
   dropItem(it);save();audit(req,"user_delete",{id:it.id});return send(200,{ok:true});
  }
  if(m=="GET"&&p=="/api/academy/status"){
   const u=userOf(req);if(!u||u.v!==true||!u.email)throw E(401,"verified Google login required");
   const sub=db.aiSubscriptions[u.sub]||null,active=!!(sub&&Number(sub.expiresAt)>Date.now());
   const price=Math.round(Number(process.env.AI_TUTOR_PRICE_BAISA)||0);
   const checkoutReady=!!(price>=100&&process.env.THAWANI_SECRET_KEY&&process.env.THAWANI_PUBLISHABLE_KEY);
   return send(200,{active,expiresAt:active?sub.expiresAt:null,priceBaisa:price>0?price:null,checkoutReady,aiReady:!!process.env.OPENAI_API_KEY});
  }
  if(m=="POST"&&p=="/api/academy/checkout"){
   const u=userOf(req);if(!u||u.v!==true||!u.email)throw E(401,"verified Google login required");
   const sub=db.aiSubscriptions[u.sub];if(sub&&Number(sub.expiresAt)>Date.now())throw E(409,"subscription already active");
   const price=Math.round(Number(process.env.AI_TUTOR_PRICE_BAISA)||0),secret=process.env.THAWANI_SECRET_KEY||"",pub=process.env.THAWANI_PUBLISHABLE_KEY||"";
   if(price<100||!secret||!pub)throw E(503,"Thawani checkout is not configured");
   if(limited("academy-checkout:"+u.sub,5,36e5))throw E(429,"too many checkout attempts");
   const live=String(process.env.THAWANI_MODE||"test").toLowerCase()==="live",base=live?"https://checkout.thawani.om":"https://uatcheckout.thawani.om";
   const origin=String(process.env.PUBLIC_BASE_URL||"https://souq-oman.onrender.com").replace(/\/+$/,"");
   const payload={client_reference_id:u.sub,mode:"payment",products:[{name:"اشتراك معلّم البرمجة - 30 يوم",quantity:1,unit_amount:price}],success_url:origin+"/academy?payment=success",cancel_url:origin+"/academy?payment=cancel",metadata:{service:"tech-oman-academy",period_days:"30"}};
   let response,data;try{response=await fetch(base+"/api/v1/checkout/session",{method:"POST",headers:{"Content-Type":"application/json","thawani-api-key":secret},body:JSON.stringify(payload)});data=await response.json()}catch(e){throw E(502,"Thawani checkout unavailable")}
   const session=data&&data.data&&data.data.session_id;
   if(!response.ok||data.success!==true||typeof session!=="string"||!session)throw E(502,"Could not create Thawani checkout");
   db.aiPayments=db.aiPayments.filter(x=>x.createdAt>Date.now()-90*864e5).slice(-900);
   db.aiPayments.push({sessionId:session,userSub:u.sub,amount:price,status:"pending",createdAt:Date.now()});save();audit(req,"academy_checkout_created",{u:u.sub.slice(-6)});
   return send(200,{sessionId:session,checkoutUrl:base+"/pay/"+encodeURIComponent(session)+"?key="+encodeURIComponent(pub)});
  }
  if(m=="POST"&&p=="/api/academy/confirm"){
   const u=userOf(req);if(!u||u.v!==true||!u.email)throw E(401,"verified Google login required");
   const b=await body(req,4e3),sid=str(b.sessionId,160),payment=db.aiPayments.find(x=>x.sessionId===sid&&x.userSub===u.sub);
   if(!payment)throw E(403,"payment session not found for this account");
   if(payment.status==="paid"){const sub=db.aiSubscriptions[u.sub];return send(200,{active:true,expiresAt:sub&&sub.expiresAt||null})}
   const secret=process.env.THAWANI_SECRET_KEY||"";if(!secret)throw E(503,"Thawani is not configured");
   const live=String(process.env.THAWANI_MODE||"test").toLowerCase()==="live",base=live?"https://checkout.thawani.om":"https://uatcheckout.thawani.om";
   let response,data;try{response=await fetch(base+"/api/v1/checkout/session/"+encodeURIComponent(sid),{headers:{"thawani-api-key":secret}});data=await response.json()}catch(e){throw E(502,"Could not verify Thawani payment")}
   const session=data&&data.data;
   if(!response.ok||data.success!==true||!session)throw E(502,"Thawani payment verification failed");
   if(String(session.client_reference_id||"")!==u.sub||Number(session.total_amount)!==Number(payment.amount)||String(session.currency||"").toUpperCase()!=="OMR")throw E(403,"payment details do not match");
   if(String(session.payment_status||"").toLowerCase()!=="paid")return send(202,{active:false,pending:true});
   const now=Date.now(),previous=db.aiSubscriptions[u.sub],start=Math.max(now,previous&&Number(previous.expiresAt)||0),expiresAt=start+30*864e5;
   db.aiSubscriptions[u.sub]={expiresAt,updatedAt:now,lastPaymentSession:sid};payment.status="paid";payment.paidAt=now;save();audit(req,"academy_subscription_activated",{u:u.sub.slice(-6),expiresAt});
   return send(200,{active:true,expiresAt});
  }
  if(m=="POST"&&p=="/api/academy/chat"){
   const u=userOf(req);if(!u||u.v!==true||!u.email)throw E(401,"verified Google login required");
   const sub=db.aiSubscriptions[u.sub];if(!sub||Number(sub.expiresAt)<=Date.now())throw E(402,"active AI tutor subscription required");
   const apiKey=process.env.OPENAI_API_KEY||"";if(!apiKey)throw E(503,"AI tutor is not configured");
   if(limited("academy-chat:"+u.sub,30,36e5))throw E(429,"message limit reached; try later");
   const b=await body(req,6e4),raw=Array.isArray(b.messages)?b.messages.slice(-10):[];
   const messages=raw.map(x=>({role:x&&x.role,content:str(x&&x.content,3000)})).filter(x=>(x.role==="user"||x.role==="assistant")&&x.content.trim());
   if(!messages.length||messages[messages.length-1].role!=="user")throw E(400,"a user question is required");
   const system="أنت معلّم برمجة ومساعد بناء مواقع ضمن منصة تقني عُمان. دورك تعليم المستخدم خطوة بخطوة وليس فقط إعطاء النتيجة. اسأل عن المستوى عند الحاجة، واشرح المصطلحات بالعربية الواضحة، وقدّم أمثلة عملية قابلة للتشغيل. ساعد في HTML وCSS وJavaScript وNode.js وقواعد البيانات وواجهات API ونشر المواقع. عندما تطلب كتابة موقع، قسّم العمل إلى ملفات واضحة وقدّم الأكواد داخل كتل Markdown fenced code، واشرح أين توضع وكيف تُشغّل. لا تطلب كلمات مرور أو مفاتيح API، ولا تضع أسراراً في الأكواد. إذا كان الطلب واسعاً، ابدأ بخطة قصيرة ثم نفّذ خطوة واحدة قابلة للفهم.";
   let response,data;try{response=await fetch("https://api.openai.com/v1/responses",{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+apiKey},body:JSON.stringify({model:process.env.OPENAI_MODEL||"gpt-6.2-astra",input:[{role:"system",content:system},...messages],max_output_tokens:1200,store:false})});data=await response.json()}catch(e){throw E(502,"AI service unavailable")}
   if(!response.ok){console.error("academy AI provider status",response.status);throw E(502,"AI response failed")}
   let answer=str(data&&data.output_text,12000);
   if(!answer&&Array.isArray(data&&data.output)){for(const item of data.output)for(const part of (item.content||[]))if(part.type==="output_text"&&part.text)answer+=part.text}
   if(!answer.trim())throw E(502,"empty AI response");
   audit(req,"academy_chat",{u:u.sub.slice(-6)});return send(200,{reply:answer});
  }
  if(m=="POST"&&p=="/api/requests"){
   if(limited("req:"+ip(req),10,36e5))throw E(429,"too many requests");
   const u=userOf(req);if(cleanSettings(db.settings).requireLogin&&!u)throw E(401,"login required");const it=build(await body(req));if(u)it.owner=u.sub;let token="";if(it.type=="ad"){token=crypto.randomBytes(16).toString("hex");it.tokHash=sha(token).toString("hex")}db.items.push(it);save();audit(req,"submit",{id:it.id,type:it.type});return send(201,{id:it.id,token});
  }
  if(m=="POST"&&p=="/api/admin/login"){
   if(limited("login:"+ip(req),8,9e5)){audit(req,"login_blocked");throw E(429,"too many attempts")}
   const b=await body(req,2e3);
   if(!checkCode(b.password)){audit(req,"login_fail");throw E(401,"wrong password")}
   const t=crypto.randomBytes(24).toString("hex");sess.set(t,Date.now()+432e5);audit(req,"login_ok");return send(200,{token:t});
  }
  if(p.startsWith("/api/admin/")){
   if(!authed(req))throw E(401,"unauthorized");
   if(m=="GET"&&p=="/api/admin/requests"){const s=u.searchParams.get("status")||"pending";return send(200,{items:db.items.filter(i=>i.status==s).sort((a,b)=>b.ts-a.ts)})}
   if(m=="GET"&&p=="/api/admin/stats"){const c=(s,t)=>db.items.filter(i=>i.status==s&&(!t||i.type==t)).length;return send(200,{pending:c("pending"),pendingAds:c("pending","ad"),pendingShops:c("pending","shop"),approved:c("approved"),rejected:c("rejected")})}
   if(m=="GET"&&p=="/api/admin/logs")return send(200,{items:tail()});
   if(m=="POST"&&p=="/api/admin/products"){
    const b=await body(req,3e5),list=Array.isArray(b.items)?b.items.slice(0,300):[],failed=[];let added=0;
    list.forEach((x,i)=>{const k=str(x&&x.shop,60).toLowerCase().replace(/^@/,""),sh=db.items.find(s=>s.type=="shop"&&(s.id==k||(s.ig&&s.ig.toLowerCase()==k)||(s.n||"").toLowerCase()==k)),pr=prods([x])[0];
     if(!sh||!pr){failed.push((i+1)+": "+str(x&&x.shop,30));return}
     sh.products=sh.products||[];if(!sh.products.some(q=>q.t==pr.t)&&sh.products.length<300){sh.products.push(pr);added++}});
    save();audit(req,"admin_products",{added,failed:failed.length});return send(200,{added,failed});
   }
   if(m=="POST"&&p=="/api/admin/import"){
    const b=await body(req,3e5),list=Array.isArray(b.items)?b.items.slice(0,100):[],failed=[];let added=0;
    list.forEach((x,i)=>{try{const it=build({...x,type:"shop"});it.status="approved";it.source="admin-import";it.products=prods(x.products);it.reviewedAt=Date.now();db.items.push(it);added++}catch(e){failed.push((i+1)+": "+str(x&&x.n,30)+" ("+e.message+")")}});
    save();audit(req,"admin_import",{added,failed:failed.length});return send(200,{added,failed});
   }
   if(m=="POST"&&p=="/api/admin/shops"){const b=await body(req);const it=build({...b,type:"shop"});it.status="approved";it.source="admin";it.reviewedAt=Date.now();db.items.push(it);save();audit(req,"admin_add_shop",{id:it.id,n:it.n});return send(201,{id:it.id})}
   if(m=="GET"&&p=="/api/admin/ratings")return send(200,{items:db.ratings.slice().sort((a,b)=>b.ts-a.ts).slice(0,300).map(r=>({id:r.id,shop:r.shop,shopName:(db.items.find(i=>i.id==r.shop)||{}).n||"",stars:r.stars,text:r.text,ts:r.ts}))});
   const dr=/^\/api\/admin\/ratings\/([a-f0-9]{12})$/.exec(p);
   if(m=="DELETE"&&dr){const n=db.ratings.length;db.ratings=db.ratings.filter(r=>r.id!=dr[1]);if(db.ratings.length==n)throw E(404,"not found");save();audit(req,"delete_rating",{id:dr[1]});return send(200,{ok:true})}
   if(m=="POST"&&p=="/api/admin/ads/delete"){
    const b=await body(req,2e5),ids=Array.isArray(b.ids)?b.ids:[],list=db.items.filter(i=>i.type=="ad"&&(b.all?(!b.status||i.status==b.status):ids.includes(i.id)));
    list.forEach(dropItem);save();audit(req,"admin_delete_ads",{count:list.length});return send(200,{deleted:list.length});
   }
   if(m=="POST"&&p=="/api/admin/bulk"){
    const b=await body(req,2e5),ids=Array.isArray(b.ids)?b.ids:[],to={hide:"hidden",show:"approved"}[b.action];if(!to)throw E(400,"bad action");
    const from=b.action=="hide"?"approved":"hidden",list=db.items.filter(i=>i.status==from&&(b.all?(!b.type||i.type==b.type):ids.includes(i.id)));
    list.forEach(i=>{i.status=to;i.reviewedAt=Date.now()});save();audit(req,"admin_bulk_"+b.action,{count:list.length});return send(200,{changed:list.length});
   }
   if(m=="POST"&&p=="/api/admin/code"){
    const b=await body(req,2e3),c=String(b.code||"");if(c.length<8||c.length>64)throw E(400,"code must be 8-64 chars");
    const salt=crypto.randomBytes(16);db.admin={salt:salt.toString("hex"),hash:crypto.scryptSync(c,salt,32).toString("hex")};save();sess.clear();audit(req,"change_code");return send(200,{ok:true});
   }
   if(m=="POST"&&p=="/api/admin/settings"){db.settings=cleanSettings(await body(req,2e4));save();audit(req,"settings",{hidden:db.settings.hidden.length});return send(200,{ok:true})}
   const ed=/^\/api\/admin\/items\/([a-f0-9]{12})\/edit$/.exec(p);
   if(m=="POST"&&ed){
    const it=db.items.find(i=>i.id==ed[1]&&i.type=="shop");if(!it)throw E(404,"not found");
    const n=build({...(await body(req,2e4)),type:"shop"});for(const k of["n","ig","web","wa","cat","city","tags","logo"])it[k]=n[k];if(n.cat!=it.cat||!it.e)it.e=n.e;
    it.editedAt=Date.now();save();audit(req,"edit",{id:it.id});return send(200,{ok:true});
   }
   const a=/^\/api\/admin\/items\/([a-f0-9]{12})\/(approve|reject|hide)$/.exec(p);
   if(m=="POST"&&a){
    const it=db.items.find(i=>i.id==a[1]);if(!it)throw E(404,"not found");
    const b=await body(req,5e3);it.status={approve:"approved",reject:"rejected",hide:"hidden"}[a[2]];it.reviewedAt=Date.now();if(a[2]=="reject")it.reason=str(b.reason,200);
    save();audit(req,a[2],{id:it.id,type:it.type});return send(200,{ok:true});
   }
   const d=/^\/api\/admin\/items\/([a-f0-9]{12})$/.exec(p);
   if(m=="DELETE"&&d){
    const i=db.items.findIndex(x=>x.id==d[1]);if(i<0)throw E(404,"not found");
    const it=db.items.splice(i,1)[0];if(it.img)fs.unlink(path.join(D,it.img.replace("/uploads/","uploads/")),()=>{});
    db.ratings=db.ratings.filter(r=>r.shop!=it.id);save();audit(req,"delete",{id:it.id,type:it.type});return send(200,{ok:true});
   }
  }
  send(404,{error:"not found"});
 }catch(e){send(e.status||500,{error:e.status?e.message:"server error"});if(!e.status)console.error(e)}
}).on("error",e=>{console.error(e.code=="EADDRINUSE"?"Port "+PORT+" is already in use. Change PORT in config.env (for example 3001) and start again.":e);process.exit(1)})
.listen(...(process.env.HOST?[PORT,process.env.HOST]:[PORT]),()=>{
 const ips=Object.values(require("os").networkInterfaces()).flat().filter(i=>i&&i.family=="IPv4"&&!i.internal).map(i=>i.address);
 console.log("\nTech Oman is running\n  Website : http://localhost:"+PORT+"\n  Admin   : http://localhost:"+PORT+"/admin   (initial login code: TARIQ123; change it after first login)");
 if(!process.env.HOST)ips.forEach(a=>console.log("  Other devices on the same Wi-Fi: http://"+a+":"+PORT));
 console.log("");
});
