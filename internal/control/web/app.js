"use strict";
let token="", user=null, selected=null, devices=[], networks=[], advancedDevices=[];
const $=id=>document.getElementById(id);
const el=(tag,value)=>{const node=document.createElement(tag);if(value!==undefined)node.textContent=String(value);return node};
function msg(value,error=false){$("message").textContent=value;$("message").classList.toggle("error",error)}
function guarded(fn){return async ev=>{if(ev)ev.preventDefault();try{await fn(ev)}catch(e){msg(e.message,true)}}}
async function api(path,method="GET",body){const headers={};if(token)headers.Authorization="Bearer "+token;if(body!==undefined)headers["Content-Type"]="application/json";const r=await fetch("/api/v1"+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),cache:"no-store"});const v=await r.json();if(!r.ok){if(r.status===401&&token)clearSession();throw Error(v.error||("HTTP "+r.status))}return v}
function clearSession(){token="";user=null;selected=null;devices=[];networks=[];$("dashboard").hidden=true;$("loginpanel").hidden=false;$("logout").hidden=true;$("identity").textContent="";$("inviteCode").value="";$("inviteResult").hidden=true;$("networks").replaceChildren();$("devices").replaceChildren();$("users").replaceChildren();$("audit").replaceChildren();$("rules").replaceChildren();$("relayNodes").replaceChildren();$("relayInvite").value="";$("relayInviteResult").hidden=true;advancedDevices=[];$("advancedDevices").replaceChildren();$("trafficRules").replaceChildren()}
function formObject(f){return Object.fromEntries(new FormData(f))}
function cell(row,value){row.append(el("td",value))}
function time(t){return t?new Date(t*1000).toLocaleString():"—"}
function showNetworks(){const root=$("networks");root.replaceChildren();for(const n of networks){const b=el("button",n.name+" · "+n.cidr);b.className="net"+(selected?.id===n.id?" selected":"");b.onclick=guarded(async()=>{selected=n;$("inviteResult").hidden=true;$("inviteCode").value="";await refreshNetwork();showNetworks()});root.append(b)}if(!networks.length)root.append(el("p","暂无网络"))}
async function refresh(){networks=await api("/networks");selected=networks.find(n=>n.id===selected?.id)||networks[0]||null;showNetworks();await refreshNetwork();$("admin").hidden=user.role!=="admin";if(user.role==="admin"){await refreshRelays();const [users,audit]=await Promise.all([api("/users"),api("/audit")]);$("users").replaceChildren(...users.map(u=>el("p",u.login+" · "+u.role)));$("audit").replaceChildren(...audit.map(a=>{const tr=el("tr");[time(a.at),a.action,a.actor,a.target].forEach(v=>cell(tr,v));return tr}))}}
async function refreshNetwork(){const n=selected;$("empty").hidden=!!n;$("networkDetail").hidden=!n;if(!n)return;const [ds,rs]=await Promise.all([api("/networks/"+n.id+"/devices"),api("/networks/"+n.id+"/rules")]);if(selected?.id!==n.id)return;devices=ds;$("networkName").textContent=n.name;$("networkInfo").textContent=n.cidr+" · 配置版本 "+n.revision;$("policy").elements.policy.value=n.policy;
$("devices").replaceChildren();for(const d of ds){const tr=el("tr");[d.name,d.ip||"—",({"pending":"待审批","approved":"已审批","revoked":"已撤销"})[d.status]||d.status,time(d.last_seen)].forEach(v=>cell(tr,v));const td=el("td");if(d.status!=="revoked"){for(const [action,name] of d.status==="pending"?[["approve","批准"],["revoke","撤销"]]:[["revoke","撤销"]]){const b=el("button",name);if(action==="revoke")b.className="danger";b.onclick=guarded(async()=>{if(action==="revoke"&&!confirm("撤销该设备的组网权限？"))return;await api("/networks/"+n.id+"/devices/"+d.id+"/"+action,"POST",{});await refresh();msg("操作成功")});td.append(b," ")}}tr.append(td);$("devices").append(tr)}
for(const name of ["a","b"]){const s=$("rule").elements[name];s.replaceChildren(...ds.filter(d=>d.status==="approved").map(d=>{const o=el("option",d.name+" · "+d.ip);o.value=d.id;return o}))}
$("rule").querySelector("button").disabled=ds.filter(d=>d.status==="approved").length<2;const names=new Map(ds.map(d=>[d.id,d.name]));$("rules").replaceChildren(...rs.map(r=>el("p",(names.get(r.a)||r.a)+" ↔ "+(names.get(r.b)||r.b)+" · "+(r.allow?"允许":"拒绝"))));if(!rs.length)$("rules").append(el("p","暂无单独规则"));await refreshAdvanced(n)}
$("login").onsubmit=guarded(async e=>{const v=await api("/auth/login","POST",formObject(e.target));token=v.token;user=v.user;e.target.reset();$("identity").textContent=user.login+" · "+user.role;$("loginpanel").hidden=true;$("dashboard").hidden=false;$("logout").hidden=false;await refresh();msg("")});
$("logout").onclick=guarded(async()=>{try{await api("/auth/logout","POST",{})}finally{clearSession();msg("")}});
$("refresh").onclick=guarded(async()=>{await refresh();msg("已刷新")});
$("createNetwork").onsubmit=guarded(async e=>{selected=await api("/networks","POST",formObject(e.target));e.target.reset();await refresh();msg("网络已创建")});
$("inviteButton").onclick=guarded(async()=>{if(!selected)return;const v=await api("/networks/"+selected.id+"/invites","POST",{ttl_seconds:3600});$("inviteCode").value=v.invite;$("inviteResult").hidden=false;msg("一次性邀请已创建，有效期 1 小时")});
$("copyInvite").onclick=guarded(async()=>{await navigator.clipboard.writeText($("inviteCode").value);msg("已复制邀请码")});
$("policy").onsubmit=guarded(async e=>{if(!selected)return;await api("/networks/"+selected.id+"/policy","PUT",formObject(e.target));await refresh();msg("访问策略已保存")});
$("rule").onsubmit=guarded(async e=>{if(!selected)return;const f=formObject(e.target);f.allow=f.allow==="true";await api("/networks/"+selected.id+"/rules","PUT",f);await refresh();msg("设备对规则已保存")});
$("createUser").onsubmit=guarded(async e=>{await api("/users","POST",formObject(e.target));e.target.reset();await refresh();msg("成员账号已创建")});

async function refreshRelays(){
 const scope=$("relayScope"), old=scope.value;scope.replaceChildren();const all=el("option","全部网络");all.value="";scope.append(all);
 for(const n of networks){const o=el("option",n.name);o.value=n.id;scope.append(o)}scope.value=old;
 const nodes=await api("/relay/nodes");$("relayNodes").replaceChildren();
 for(const n of nodes){const tr=el("tr");const net=networks.find(x=>x.id===n.network_id);[n.id,n.region+" / "+(n.network_id?(net?.name||n.network_id):"全部"),n.state==="revoked"?"已撤销":!n.registered?"待注册":!n.online?"离线":n.state==="draining"?"维护中":"在线",n.connections+" / "+n.max_connections,n.ingress_bytes+" / "+n.egress_bytes,n.dropped_packets,time(n.last_seen)].forEach(v=>cell(tr,v));const td=el("td");
 if(n.state!=="revoked"){for(const [state,label] of [[n.state==="draining"?"active":"draining",n.state==="draining"?"恢复":"维护"],["revoked","撤销"]]){const b=el("button",label);b.onclick=guarded(async()=>{if(state==="revoked"&&!confirm("永久撤销该节点？"))return;await api("/relay/nodes/"+encodeURIComponent(n.id)+"/state","PUT",{state});await refreshRelays();msg("节点状态已更新")});td.append(b," ")}const limits=el("button","限额");limits.onclick=guarded(async()=>{const max=prompt("最大连接数（2-256）",n.max_connections);if(max===null)return;const rate=prompt("节点字节/秒（65536-1073741824）",n.bytes_per_second);if(rate===null)return;await api("/relay/nodes/"+encodeURIComponent(n.id)+"/limits","PUT",{max_connections:Number(max),bytes_per_second:Number(rate)});await refreshRelays();msg("限额已更新")});td.append(limits)}
 tr.append(td);$("relayNodes").append(tr)}
}
$("createRelay").onsubmit=guarded(async e=>{const f=formObject(e.target);for(const k of ["priority","max_connections","bytes_per_second"])f[k]=Number(f[k]);const r=await api("/relay/nodes","POST",f);$("relayInvite").value=r.invite;$("relayInviteResult").hidden=false;await refreshRelays();msg("节点邀请已创建")});
$("copyRelayInvite").onclick=guarded(async()=>{await navigator.clipboard.writeText($("relayInvite").value);msg("已复制节点邀请")});

async function refreshAdvanced(n){
 const view=await api("/networks/"+n.id+"/advanced");if(selected?.id!==n.id)return;
 advancedDevices=view.devices;const approved=devices.filter(d=>d.status==="approved"), names=new Map(approved.map(d=>[d.id,d.name+" · "+d.ip]));
 for(const field of [$("advancedDeviceSelect"),$("trafficRule").elements.a,$("trafficRule").elements.b]){
  const old=field.value;field.replaceChildren(...approved.map(d=>{const o=el("option",names.get(d.id));o.value=d.id;return o}));if(approved.some(d=>d.id===old))field.value=old;
 }
 $("advancedDevice").querySelector("button").disabled=!approved.length;$("trafficRule").querySelector("button").disabled=approved.length<2;
 $("advancedDevices").replaceChildren(...advancedDevices.map(d=>el("p",(names.get(d.device_id)||d.device_id)+" · "+(d.subnets||[]).join(", ")+" · "+(d.dns_label?d.dns_label+".network-ex.internal":"无别名"))));
 $("trafficRules").replaceChildren(...view.rules.map(r=>el("p",(names.get(r.a)||r.a)+" ↔ "+(names.get(r.b)||r.b)+" · "+(r.policy.services.length?r.policy.services.map(s=>s.protocol+(s.port?":"+s.port:"")).join(", "):"拒绝全部服务"))));
 fillAdvancedDevice();
 $("exitSection").hidden=user?.role!=="admin";
 if(user?.role==="admin"){
  for(const field of [$("exitGrant").elements.client,$("exitGrant").elements.gateway]){
   const old=field.value;field.replaceChildren(...approved.map(d=>{const o=el("option",names.get(d.id));o.value=d.id;return o}));if(approved.some(d=>d.id===old))field.value=old;
  }
  const grants=await api("/networks/"+n.id+"/exit");if(selected?.id!==n.id)return;
  $("exitGrants").replaceChildren(...grants.map(g=>el("p",(names.get(g.client)||g.client)+" → "+(names.get(g.gateway)||g.gateway)+" · "+g.targets.join(", "))));
 }
}
function fillAdvancedDevice(){const f=$("advancedDevice").elements;const d=advancedDevices.find(d=>d.device_id===f.device.value);f.subnets.value=(d?.subnets||[]).join(", ");f.dns_label.value=d?.dns_label||"";f.subnets.disabled=user?.role!=="admin"}
$("advancedDeviceSelect").onchange=fillAdvancedDevice;
$("advancedDevice").onsubmit=guarded(async e=>{if(!selected)return;const f=e.target.elements;await api("/networks/"+selected.id+"/devices/"+f.device.value+"/advanced","PUT",{subnets:f.subnets.value.split(",").map(x=>x.trim()).filter(Boolean),dns_label:f.dns_label.value.trim()});await refresh();msg("设备高级配置已保存")});
$("trafficRule").onsubmit=guarded(async e=>{if(!selected)return;const f=formObject(e.target);let policy=null;if(f.mode==="restricted"){const services=f.services.split(",").map(x=>x.trim().toLowerCase()).filter(Boolean).map(x=>{if(x==="icmp")return{protocol:x};const m=/^(tcp|udp):([0-9]+)$/.exec(x);if(!m||Number(m[2])<1||Number(m[2])>65535)throw Error("无效服务格式："+x);return{protocol:m[1],port:Number(m[2])}});policy={services}}await api("/networks/"+selected.id+"/traffic","PUT",{a:f.a,b:f.b,policy});await refresh();msg("流量规则已保存")});

$("exitGrant").onsubmit=guarded(async e=>{if(!selected||user?.role!=="admin")return;const f=formObject(e.target);const targets=f.targets.split(",").map(x=>x.trim()).filter(Boolean);if(!targets.length)throw Error("请填写指定公网 IPv4，或使用撤销按钮");await api("/networks/"+selected.id+"/exit","PUT",{client:f.client,gateway:f.gateway,targets});await refresh();msg("出口授权已保存")});
$("removeExit").onclick=guarded(async()=>{if(!selected||user?.role!=="admin"||!confirm("撤销此设备的出口授权？"))return;await api("/networks/"+selected.id+"/exit","PUT",{client:$("exitGrant").elements.client.value,gateway:"",targets:[]});await refresh();msg("出口授权已撤销")});
