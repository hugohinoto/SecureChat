const $=s=>document.querySelector(s);
const notice=$("#notice"),consoleRoot=$("#console");
let page=0,currentAdmin="";
function message(text,type=""){notice.textContent=text;notice.className="notice "+type;}
async function api(path,options={}){
 const response=await fetch(path,{method:options.method||"GET",credentials:"same-origin",cache:"no-store",headers:{"Accept":"application/json",...(options.body?{"Content-Type":"application/json"}:{})},...(options.body?{body:JSON.stringify(options.body)}:{})});
 const data=response.status===204?{}:await response.json().catch(()=>({}));
 if(!response.ok){const messages={UNAUTHENTICATED:"ログインが必要です。SecureChatに管理者アカウントでログインしてください。",ADMIN_REQUIRED:"このアカウントには管理者権限がありません。",ADMIN_REAUTH_REQUIRED:"管理者操作には直近15分以内のログインが必要です。SecureChatからログアウトし、再ログインしてください。",ADMIN_ACCOUNT_PROTECTED:"管理者アカウントはこの画面から削除できません。",CANNOT_DELETE_SELF:"自分自身のアカウントは削除できません。",CONFIRMATION_MISMATCH:"確認用ユーザーIDが一致しません。"};
 throw new Error(messages[data.error]||data.message||data.error||("HTTP "+response.status));}
 return data;
}
function date(value){if(!value)return "—";const d=new Date(Number(value));return Number.isNaN(d.getTime())?"—":new Intl.DateTimeFormat("ja-JP",{dateStyle:"medium",timeStyle:"short"}).format(d);}
function cell(row,value){const td=document.createElement("td");td.textContent=value??"—";row.append(td);return td;}
async function loadOverview(){
 const d=await api("/api/admin/overview");
 $("#stat-users").textContent=d.users;$("#stat-admins").textContent=d.administrators;$("#stat-sessions").textContent=d.activeSessions;$("#stat-messages").textContent=d.activeMessages;$("#stat-invites").textContent=d.pendingInvitations;$("#stat-actions").textContent=d.adminActions24h;
 $("#worker-note").textContent=d.workerErrors+" DB確認時刻: "+date(d.checkedAt);
}
async function loadUsers(){
 const q=$("#user-query").value.trim(),d=await api("/api/admin/users?q="+encodeURIComponent(q)+"&page="+page),body=$("#users");body.replaceChildren();
 for(const u of d.users){const tr=document.createElement("tr");cell(tr,u.user_id);const role=cell(tr,Number(u.is_admin)===1?"管理者":"一般ユーザー");if(Number(u.is_admin)===1)role.className="role-admin";cell(tr,date(u.created_at));cell(tr,date(u.last_login_at));const action=cell(tr,"");
 if(Number(u.is_admin)!==1){const b=document.createElement("button");b.className="delete-user";b.textContent="削除";b.addEventListener("click",()=>deleteUser(u));action.append(b);}else action.textContent="保護中";
 body.append(tr);}
 $("#page-label").textContent=(page+1)+"ページ / "+Math.max(1,Math.ceil(d.total/d.pageSize))+"ページ · "+d.total+"件";
 $("#prev-page").disabled=page<=0;$("#next-page").disabled=(page+1)*d.pageSize>=d.total;
}
async function deleteUser(u){
 if(!confirm("@"+u.user_id+" を完全に削除します。連絡先・会話・メッセージ・セッションも削除されます。この操作は取り消せません。"))return;
 const typed=prompt("誤操作防止のため、ユーザーID「"+u.user_id+"」をそのまま入力してください。");
 if(typed===null)return;
 try{await api("/api/admin/users/delete",{method:"POST",body:{userId:u.id,confirmUserId:typed}});message("@"+u.user_id+" を削除しました。","ok");await Promise.all([loadOverview(),loadUsers(),loadLogs()]);}
 catch(e){message(e.message,"error");}
}
async function loadAnnouncements(){
 const d=await api("/api/admin/announcements"),root=$("#announcements");root.replaceChildren();
 for(const a of d.announcements){const card=document.createElement("article");card.className="announcement-item";const copy=document.createElement("div");const h=document.createElement("h3");h.textContent=a.title;const p=document.createElement("p");p.textContent=a.body;const small=document.createElement("small");small.textContent=(Number(a.published)===1?"公開中":"下書き")+" · 作成 "+date(a.created_at);copy.append(h,p,small);
 const actions=document.createElement("div");actions.className="item-actions";const toggle=document.createElement("button");toggle.textContent=Number(a.published)===1?"非公開にする":"公開する";toggle.addEventListener("click",async()=>{try{await api("/api/admin/announcements/"+a.id,{method:"PUT",body:{title:a.title,body:a.body,published:Number(a.published)!==1}});await loadAnnouncements();await loadOverview();message("公開状態を更新しました。","ok");}catch(e){message(e.message,"error");}});
 const edit=document.createElement("button");edit.textContent="編集";edit.addEventListener("click",async()=>{const title=prompt("タイトル",a.title);if(title===null)return;const body=prompt("本文",a.body);if(body===null)return;try{await api("/api/admin/announcements/"+a.id,{method:"PUT",body:{title,body,published:Number(a.published)===1}});await loadAnnouncements();message("お知らせを更新しました。","ok");}catch(e){message(e.message,"error");}});
 const del=document.createElement("button");del.className="danger";del.textContent="削除";del.addEventListener("click",async()=>{if(!confirm("このお知らせを削除しますか？"))return;try{await api("/api/admin/announcements/"+a.id,{method:"DELETE"});await loadAnnouncements();await loadOverview();message("お知らせを削除しました。","ok");}catch(e){message(e.message,"error");}});
 actions.append(toggle,edit,del);card.append(copy,actions);root.append(card);}
 if(!d.announcements.length){const p=document.createElement("p");p.className="muted";p.textContent="お知らせはまだありません。";root.append(p);}
}
async function loadLogs(){
 const d=await api("/api/admin/audit-logs"),body=$("#logs");body.replaceChildren();
 for(const log of d.logs){const tr=document.createElement("tr");cell(tr,date(log.created_at));cell(tr,log.admin_user_id||"(削除済み管理者)");cell(tr,log.action);cell(tr,log.target_user_id||"—");let detail=log.details_json||"";try{detail=JSON.stringify(JSON.parse(detail));}catch{}cell(tr,detail);body.append(tr);}
 if(!d.logs.length){const tr=document.createElement("tr");cell(tr,"記録はありません。");body.append(tr);}
}
async function refreshAll(){await Promise.all([loadOverview(),loadUsers(),loadAnnouncements(),loadLogs()]);}
$("#announcement-form").addEventListener("submit",async e=>{e.preventDefault();const title=$("#announcement-title").value.trim(),body=$("#announcement-body").value.trim(),published=$("#announcement-publish").checked;try{await api("/api/admin/announcements",{method:"POST",body:{title,body,published}});$("#announcement-form").reset();$("#announcement-publish").checked=true;await Promise.all([loadAnnouncements(),loadOverview()]);message(published?"お知らせを公開しました。":"下書きを保存しました。","ok");}catch(err){message(err.message,"error");}});
$("#user-search").addEventListener("submit",async e=>{e.preventDefault();page=0;try{await loadUsers();}catch(err){message(err.message,"error");}});
$("#user-reset").addEventListener("click",async()=>{$("#user-query").value="";page=0;await loadUsers();});
$("#prev-page").addEventListener("click",async()=>{page=Math.max(0,page-1);await loadUsers();});
$("#next-page").addEventListener("click",async()=>{page++;await loadUsers();});
$("#refresh-logs").addEventListener("click",()=>loadLogs().catch(e=>message(e.message,"error")));
$("#logout").addEventListener("click",async()=>{try{await fetch("/api/auth/logout",{method:"POST",credentials:"same-origin",headers:{"Accept":"application/json"}});}finally{location.href="/";}});
(async()=>{try{const d=await api("/api/admin/overview");const me=await fetch("/api/auth/me",{credentials:"same-origin",cache:"no-store"}).then(r=>r.json());currentAdmin=me.user?.userId||"管理者";$("#admin-identity").textContent="@"+currentAdmin;consoleRoot.hidden=false;notice.hidden=true;await refreshAll();}catch(e){message(e.message,"error");consoleRoot.hidden=true;}})();
