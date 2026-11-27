import { initI18n, t, getLocale, translateText } from "./i18n.js";

initI18n();

const $=s=>document.querySelector(s);
const notice=$("#report-notice"),panel=$("#report-panel"),form=$("#report-form"),submit=$("#report-submit"),myReportsPanel=$("#my-reports-panel"),myReportsRoot=$("#my-reports");
function show(text,type=""){notice.textContent=translateText(text);notice.className="notice "+type;}
async function api(path,options={}){
 const response=await fetch(path,{method:options.method||"GET",credentials:"same-origin",cache:"no-store",headers:{"Accept":"application/json",...(options.body?{"Content-Type":"application/json"}:{})},...(options.body?{body:JSON.stringify(options.body)}:{})});
 const data=await response.json().catch(()=>({}));
 if(!response.ok){const message=data.error==="UNAUTHENTICATED"?t("bug.loginRequired"):data.error==="DATA_ENCRYPTION_NOT_CONFIGURED"?t("bug.encryptionNotConfigured")+" 管理者へ連絡してください。":data.error==="RATE_LIMITED"?t("bug.rateLimited"):data.error||t("bug.sendFailed");throw new Error(message);}
 return data;
}

const reportTabs=document.querySelectorAll("[data-report-target]");
function activateReportView(target){
 document.querySelectorAll("[data-report-view]").forEach(panel=>{panel.hidden=panel.id!==target;});
 reportTabs.forEach(button=>{const active=button.dataset.reportTarget===target;button.classList.toggle("active",active);button.setAttribute("aria-selected",String(active));});
}
reportTabs.forEach(button=>button.addEventListener("click",()=>activateReportView(button.dataset.reportTarget)));
activateReportView("report-panel");

(async()=>{
 try{
  const me=await api("/api/auth/me");
  if(!me.authenticated){show(t("bug.loginRequired"),"error");return;}
  panel.hidden=false;myReportsPanel.hidden=false;show(getLocale()==="ja"?"@"+me.user.userId+" として報告できます。":"Reporting as @"+me.user.userId+".","ok");await loadMyReports();
 }catch(e){show(e.message,"error");}
})();
form.addEventListener("submit",async e=>{
 e.preventDefault();submit.disabled=true;
 const body={category:$("#report-category").value,title:$("#report-title").value,description:$("#report-description").value,steps:$("#report-steps").value,expected:$("#report-expected").value,actual:$("#report-actual").value};
 try{await api("/api/bug-reports",{method:"POST",body});form.reset();show(t("bug.submitOk"),"ok");await loadMyReports();}
 catch(error){show(error.message,"error");}
 finally{submit.disabled=false;}
});

function reportStatus(value){return ({open:t("bug.reportStatus.open"),triaged:t("bug.reportStatus.triaged"),resolved:t("bug.reportStatus.resolved")})[value]||value;}
function reportDate(value){if(!value)return "—";const d=new Date(Number(value));return Number.isNaN(d.getTime())?"—":new Intl.DateTimeFormat(getLocale()==="ja"?"ja-JP":"en-US",{dateStyle:"medium",timeStyle:"short"}).format(d);}
async function loadMyReports(){
 const data=await api("/api/bug-reports");myReportsRoot.replaceChildren();
 for(const item of data.reports){
  const card=document.createElement("article");card.className="announcement-item";
  const content=document.createElement("div"),title=document.createElement("h3"),meta=document.createElement("small"),description=document.createElement("p");
  title.dataset.userContent="true";title.textContent=item.report.title;meta.textContent=reportDate(item.createdAt)+" · "+(getLocale()==="ja"?"状態：":"Status: ")+reportStatus(item.status);
  description.dataset.userContent="true";description.textContent=item.report.description;content.append(title,meta,description);
  const replies=document.createElement("div");replies.className="bug-report-thread";
  const heading=document.createElement("strong");heading.textContent="管理者からの返信";replies.append(heading);
  for(const reply of item.replies||[]){
   const entry=document.createElement("article");entry.className="bug-report-reply";
   const date=document.createElement("small");date.textContent=reportDate(reply.createdAt);
   const message=document.createElement("p");message.dataset.userContent="true";message.textContent=reply.message;entry.append(date,message);replies.append(entry);
  }
  if(!(item.replies||[]).length){const empty=document.createElement("p");empty.className="muted";empty.textContent="返信はまだありません。返信が届くとここに表示されます。";replies.append(empty);}
  content.append(replies);card.append(content);myReportsRoot.append(card);
 }
 if(!data.reports.length){const empty=document.createElement("p");empty.className="muted";empty.textContent="送信済みの報告はありません。";myReportsRoot.append(empty);}
}
$("#refresh-my-reports")?.addEventListener("click",()=>loadMyReports().catch(error=>show(error.message,"error")));

document.addEventListener("securechat:localechange", () => {
  if (typeof loadMyReports === "function") loadMyReports().catch(()=>{});
});
