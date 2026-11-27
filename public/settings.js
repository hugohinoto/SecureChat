import { initI18n } from "./i18n.js";
initI18n();
const $=s=>document.querySelector(s);
async function api(path,options={}) {
  const headers={Accept:"application/json",...(options.headers||{})};
  if(options.body!==undefined)headers["Content-Type"]="application/json";
  const response=await fetch(path,{credentials:"same-origin",cache:"no-store",...options,headers,
    ...(options.body!==undefined?{body:JSON.stringify(options.body)}:{})});
  const data=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(data.message||data.error||"リクエストに失敗しました");
  return data;
}
async function loadAccount() {
  try {
    const data=await api("/api/auth/me");const user=data.user||data;
    const id=user.userId||user.user_id||user.id||"";
    $("#settings-user-id").textContent=id?"@"+id:"ログイン済み";$("#settings-session").textContent="有効";
    return id;
  } catch(error) {
    $("#settings-user-id").textContent="未ログイン";$("#settings-session").textContent="ログインが必要です";
    $("#settings-logout").disabled=true;return "";
  }
}
async function loadKeyBackupStatus() {
  const status=$("#settings-key-backup-status"),detail=$("#settings-key-backup-detail");
  try {
    const data=await api("/api/keys/backup");
    if(data.backupAvailable){status.textContent="暗号化バックアップ: 準備完了";detail.textContent="このアカウントの秘密鍵はパスワードで暗号化されたバックアップに保存されています。別端末では同じアカウントのパスワードで復元できます。";}
    else if(data.identityMode==="legacy-local-only"){status.textContent="暗号化バックアップ: 未作成（元端末限定）";detail.textContent="この鍵は現在のブラウザー内だけにあります。サイトデータを削除・初期化しないでください。";}
    else if(data.identityMode==="setup-required"){status.textContent="暗号化バックアップ: 未作成";detail.textContent="旧形式の秘密鍵は元のブラウザー内だけにあります。再ログインだけではバックアップを作成できません。元端末とサイトデータを保持してください。";}
    else{status.textContent="暗号鍵: 未登録";detail.textContent="このアカウントにはまだ暗号鍵が登録されていません。";}
  } catch(error) {status.textContent="暗号鍵の状態を取得できません";detail.textContent="ログイン状態を確認してから再読み込みしてください。秘密鍵やサイトデータは削除しないでください。";}
}
function formatTime(value) {
  if(!Number.isFinite(Number(value)))return "不明";
  return new Intl.DateTimeFormat("ja-JP",{dateStyle:"medium",timeStyle:"short"}).format(new Date(Number(value)));
}
function readCurrentDeviceId(userId) {
  return new Promise((resolve,reject)=>{
    const request=indexedDB.open("securechat-crypto-v2-vault",1);
    request.onerror=()=>reject(request.error);
    request.onsuccess=()=>{
      const db=request.result;
      if(!db.objectStoreNames.contains("devices")){db.close();resolve("");return;}
      const get=db.transaction("devices","readonly").objectStore("devices").get(userId);
      get.onsuccess=()=>{const id=typeof get.result?.deviceId==="string"?get.result.deviceId:"";db.close();resolve(id);};
      get.onerror=()=>{db.close();reject(get.error);};
    };
  });
}
async function loadDevices(userId) {
  const status=$("#settings-device-status"),list=$("#crypto-v2-device-list");
  list.replaceChildren();
  if(!userId){status.textContent="端末一覧を見るにはログインしてください。";return;}
  try {
    const currentDeviceId=await readCurrentDeviceId(userId);
    if(!currentDeviceId){status.textContent="この端末のV2鍵が未登録です。チャット画面を開き、端末登録が完了してから再読み込みしてください。";return;}
    const headers={"X-SecureChat-Device":currentDeviceId};
    const data=await api("/api/crypto/devices",{headers});
    const devices=Array.isArray(data.devices)?data.devices:[];
    status.textContent=devices.length+" 台の端末";
    if(!devices.length){list.textContent="登録済み端末はありません。";return;}
    for(const device of devices) {
      const row=document.createElement("article");row.className="crypto-v2-device-row";
      const info=document.createElement("div");info.className="crypto-v2-device-info";
      const title=document.createElement("strong");title.textContent=(device.displayName||"SecureChat端末")+" · "+(device.deviceId===currentDeviceId?"この端末":device.deviceId);
      const meta=document.createElement("span");meta.textContent=device.revokedAt?"失効済み · "+formatTime(device.revokedAt):"最終確認: "+formatTime(device.lastSeenAt);
      const created=document.createElement("small");created.textContent="登録: "+formatTime(device.createdAt);
      info.append(title,meta,created);row.append(info);
      if(device.deviceId!==currentDeviceId) {
        const button=document.createElement("button");button.type="button";button.className="crypto-v2-revoke-button";
        button.textContent=device.revokedAt?"失効通知を再送":"この端末を失効";
        button.addEventListener("click",async()=>{
          const prompt=device.revokedAt?"この端末の失効通知を再送しますか？":"この端末を失効しますか？既に保存・複製されたデータは遠隔消去されません。";
          if(!confirm(prompt))return;
          button.disabled=true;
          try {await api("/api/crypto/devices/"+encodeURIComponent(device.deviceId)+"/revoke",{method:"POST",headers,body:{}});await loadDevices(userId);}
          catch(error){status.textContent="端末の失効に失敗しました: "+error.message;button.disabled=false;}
        });
        row.append(button);
      } else {
        const current=document.createElement("span");current.className="crypto-v2-current-device";current.textContent="使用中";row.append(current);
      }
      list.append(row);
    }
  } catch(error) {status.textContent="端末一覧を取得できません: "+error.message;}
}
function refreshNotifications() {
  const button=$("#settings-notifications"),status=$("#settings-notification-status");
  if(!("Notification"in window)){button.hidden=true;status.textContent="このブラウザーは通知に対応していません。";return;}
  if(Notification.permission==="granted"){button.textContent="通知は有効です";button.disabled=true;status.textContent="新着メッセージの通知を受け取れます。";}
  else if(Notification.permission==="denied"){button.textContent="ブラウザー設定で許可してください";button.disabled=true;status.textContent="通知がブラウザー側でブロックされています。";}
  else{button.textContent="通知を有効にする";button.disabled=false;status.textContent="通知の許可を求めます。";}
}
$("#settings-notifications").addEventListener("click",async()=>{try{await Notification.requestPermission();}catch{}refreshNotifications();});
$("#settings-logout").addEventListener("click",async event=>{
  const button=event.currentTarget;button.disabled=true;
  try{await api("/api/auth/logout",{method:"POST"});location.href="/";}
  catch(error){$("#settings-session").textContent=error.message;button.disabled=false;}
});
(async()=>{const userId=await loadAccount();await Promise.all([loadKeyBackupStatus(),loadDevices(userId)]);refreshNotifications();})();
