// Web.Index backend — public API, admin API, login and media, all in one Worker. Storage: one KV namespace (DATA).
import {USERNAME,PASSWORD_HASH} from "./credentials.js";
const enc=new TextEncoder(),S=(v,n)=>String(v??"").slice(0,n),T=(v,n)=>S(v,n).trim();
const hex=u=>[...new Uint8Array(u)].map(b=>b.toString(16).padStart(2,"0")).join("");
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const sha=async s=>hex(await crypto.subtle.digest("SHA-256",enc.encode(s)));
const eq=(a,b)=>{if(a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0};
const J=(o,s=200,h={})=>new Response(JSON.stringify(o),{status:s,headers:{"Content-Type":"application/json","Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff",...h}});
const url=v=>{try{const x=new URL(String(v));return/^https?:$/.test(x.protocol)?x.href.slice(0,300):""}catch{return""}};
const mid=v=>/^[a-f0-9]{16}$/.test(v)?v:"";

/* ---- PASSWORD FORMULA ----------------------------------------------------------------
   stored = "pbkdf2$100000$" + base64(salt) + "$" + base64( PBKDF2-HMAC-SHA256(password, salt, 100000 iterations, 32 bytes) )
   The password is never stored or compared in plain text; the same formula is used by tools/hash.html. */
async function verify(pw,st){try{const[a,it,salt,h]=String(st).split("$");if(a!=="pbkdf2"||!h||+it>1e5)return false;
 const k=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveBits"]);
 const bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:Uint8Array.from(atob(salt),c=>c.charCodeAt(0)),iterations:+it},k,256);
 return eq(btoa(String.fromCharCode(...new Uint8Array(bits))),h)}catch{return false}}

const blank=()=>({members:[1,2,3,4].map(i=>({id:"m"+i,status:"draft",name:{},role:{},bio:{},social:"",image:""})),projects:[],logs:[]});
const getDoc=async env=>(await env.DATA.get("site","json"))||blank();
const putDoc=(env,d)=>env.DATA.put("site",JSON.stringify(d));
const note=(d,a,t)=>{d.logs=[{a,t:t||"",ts:Date.now()},...(d.logs||[])].slice(0,20)};

async function sess(req,env){const m=/(?:^|;\s*)wi_sid=([a-f0-9]{64})/.exec(req.headers.get("Cookie")||"");if(!m)return null;
 const th=await sha(m[1]),csrf=await env.DATA.get("s:"+th);return csrf?{th,csrf}:null}

async function login(req,env){
 const ip=req.headers.get("CF-Connecting-IP")||"unknown",rk="rl:"+ip,n=+(await env.DATA.get(rk))||0;
 if(n>=5)return J({error:"throttled"},429);
 const hash=env.ADMIN_PASSWORD_HASH||PASSWORD_HASH;if(!hash)return J({error:"not_configured"},503);
 const b=await req.json().catch(()=>null);if(!b)return J({error:"bad"},400);
 const pwOk=await verify(S(b.password,256),hash),userOk=eq(S(b.username,64),env.ADMIN_USERNAME||USERNAME);
 if(!(pwOk&&userOk)){await env.DATA.put(rk,String(n+1),{expirationTtl:900});return J({error:"invalid"},401)}
 await env.DATA.delete(rk);
 const tok=rnd(32),csrf=rnd(16);await env.DATA.put("s:"+await sha(tok),csrf,{expirationTtl:28800});
 const d=await getDoc(env);note(d,"login");await putDoc(env,d);
 return J({ok:true},200,{"Set-Cookie":`wi_sid=${tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`})}

const L=(o,n)=>({fa:T(o?.fa,n),en:T(o?.en,n)});
function clean(k,d){if(k==="member")return{name:L(d.name,80),role:L(d.role,80),bio:L(d.bio,400),social:url(d.social),image:mid(d.image)};
 return{title:L(d.title,100),desc:L(d.desc,500),cat:L(d.cat,40),tags:(Array.isArray(d.tags)?d.tags:[]).slice(0,10).map(x=>T(x,30)).filter(Boolean),demo:url(d.demo),repo:url(d.repo),featured:!!d.featured,cover:mid(d.cover),video:mid(d.video)}}

async function item(req,env,m){
 const b=await req.json().catch(()=>null);if(!b)return J({error:"bad"},400);const d=await getDoc(env);
 if(m==="DELETE"){const n=d.projects.length;d.projects=d.projects.filter(p=>p.id!==b.id);note(d,"delete",S(b.id,20));await putDoc(env,d);return J({ok:d.projects.length<n})}
 const st=["draft","published","unpublished"].includes(b.status)?b.status:"draft",k=b.kind==="member"?"member":"project",c=clean(k,b.data||{});
 if(k==="member"){const x=d.members.find(y=>y.id===b.id);if(!x)return J({error:"bad"},400);Object.assign(x,c,{status:st})}
 else{let p=d.projects.find(y=>y.id===b.id);if(!p){p={id:rnd(6),ts:Date.now()};d.projects.push(p)}Object.assign(p,c,{status:st,upd:Date.now()})}
 note(d,st==="published"?"publish":"save",S(b.id,20));await putDoc(env,d);return J({ok:true})}

/* ---- media (KV): type is detected from the file's first bytes, never from its name ---- */
function sniff(buf){const u=new Uint8Array(buf.slice(0,16)),h=hex(u),a=String.fromCharCode(...u.slice(4,12));
 if(h.startsWith("ffd8ff"))return["image/jpeg",8e6];if(h.startsWith("89504e470d0a1a0a"))return["image/png",8e6];
 if(h.startsWith("52494646")&&h.slice(16,24)==="57454250")return["image/webp",8e6];
 if(/^ftyp(isom|iso\d|mp4\d|avc1|M4V |dash|MSNV)/.test(a))return["video/mp4",24e6];if(h.startsWith("1a45dfa3"))return["video/webm",24e6];return null}
async function mlist(env){const o=await env.DATA.list({prefix:"m:",limit:1000});
 return o.keys.map(k=>({id:k.name.slice(2),name:k.metadata?.n||"",type:k.metadata?.t||"",size:k.metadata?.s||0,ts:k.metadata?.ts||0})).sort((a,b)=>b.ts-a.ts)}
async function media(req,env,u){
 if(req.method==="PUT"){if((+req.headers.get("Content-Length")||0)>25e6)return J({error:"big"},413);
  const buf=await req.arrayBuffer(),ty=sniff(buf);if(!ty)return J({error:"type"},415);if(buf.byteLength>ty[1])return J({error:"big"},413);
  const id=rnd(8),name=T(u.searchParams.get("name"),80).replace(/[^\w.\- \u0600-\u06FF]/g,"_")||"file";
  await env.DATA.put("m:"+id,buf,{metadata:{n:name,t:ty[0],s:buf.byteLength,ts:Date.now()}});
  const d=await getDoc(env);note(d,"upload",id);await putDoc(env,d);return J({ok:true,id})}
 if(req.method==="DELETE"){const b=await req.json().catch(()=>null),id=b&&mid(b.id);if(!id)return J({error:"bad"},400);
  const d=await getDoc(env);if(JSON.stringify([d.members,d.projects]).includes(id))return J({error:"inuse"},409);
  await env.DATA.delete("m:"+id);note(d,"media_delete",id);await putDoc(env,d);return J({ok:true})}
 return J({error:"method"},405)}
async function serve(req,env,id){const{value,metadata:md}=await env.DATA.getWithMetadata("m:"+id,"arrayBuffer");if(!value)return new Response("Not found",{status:404});
 const n=value.byteLength,h={"Content-Type":md.t,"Accept-Ranges":"bytes","X-Content-Type-Options":"nosniff","Cache-Control":"public, max-age=31536000, immutable","Content-Security-Policy":"default-src 'none'"};
 const r=/^bytes=(\d*)-(\d*)$/.exec(req.headers.get("Range")||"");
 if(r){const a=r[1]===""?n-+r[2]:+r[1],b=r[1]===""||r[2]===""?n-1:Math.min(+r[2],n-1);
  if(!(a>=0&&a<=b))return new Response(null,{status:416,headers:{"Content-Range":`bytes */${n}`}});
  return new Response(value.slice(a,b+1),{status:206,headers:{...h,"Content-Range":`bytes ${a}-${b}/${n}`}})}
 return new Response(value,{headers:h})}

async function pub(env){const d=await getDoc(env),u=i=>i?"/media/"+i:"";
 return J({members:d.members.map(m=>m.status==="published"?{name:m.name,role:m.role,bio:m.bio,social:m.social,image:u(m.image)}:null),
  projects:d.projects.filter(p=>p.status==="published").sort((a,b)=>(b.featured?1:0)-(a.featured?1:0)||b.ts-a.ts)
   .map(p=>({title:p.title,desc:p.desc,cat:p.cat,tags:p.tags,demo:p.demo,repo:p.repo,cover:u(p.cover),video:u(p.video)}))},200,{"Cache-Control":"public, max-age=30"})}

const guard=(r,n)=>{r=new Response(r.body,r);r.headers.set("X-Content-Type-Options","nosniff");r.headers.set("X-Frame-Options","DENY");r.headers.set("Referrer-Policy","same-origin");
 r.headers.set("X-Robots-Tag","noindex, nofollow");r.headers.set("Cache-Control","private, no-store");
 r.headers.set("Content-Security-Policy",`default-src 'self'; script-src 'nonce-${n}'; style-src 'nonce-${n}' https://fonts.googleapis.com; style-src-attr 'unsafe-inline'; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`);return r};
async function page(req,env){const r=await env.ASSETS.fetch(new Request(new URL("/admin",req.url)));if(!r.ok)return r;
 const n=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))),html=(await r.text()).replaceAll("{{N}}",n);
 return guard(new Response(html,{headers:{"Content-Type":"text/html; charset=utf-8"}}),n)}

export default{async fetch(req,env){
 const u=new URL(req.url),p=u.pathname,m=req.method;
 try{
  if(p==="/api/content"&&m==="GET")return pub(env);
  const mm=/^\/media\/([a-f0-9]{16})$/.exec(p);if(mm&&(m==="GET"||m==="HEAD"))return serve(req,env,mm[1]);
  if(p==="/api/admin/login"&&m==="POST")return login(req,env);
  if(p.startsWith("/api/admin/")){
   const s=await sess(req,env);if(!s)return J({error:"unauthorized"},401);const o=req.headers.get("Origin");
   if(m!=="GET"&&(!eq(req.headers.get("X-CSRF-Token")||"",s.csrf)||(o&&o!==u.origin)))return J({error:"forbidden"},403);
   if(p==="/api/admin/me")return J({user:env.ADMIN_USERNAME||USERNAME,csrf:s.csrf});
   if(p==="/api/admin/data")return J({...await getDoc(env),media:await mlist(env)});
   if(p==="/api/admin/logout"&&m==="POST"){await env.DATA.delete("s:"+s.th);return J({ok:true},200,{"Set-Cookie":"wi_sid=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"})}
   if(p==="/api/admin/item")return item(req,env,m);
   if(p==="/api/admin/media")return media(req,env,u);
   return J({error:"not found"},404)}
  if(p==="/admin"||p==="/admin/")return page(req,env);
  return env.ASSETS.fetch(req)
 }catch(e){return J({error:"server"},500)}}};
