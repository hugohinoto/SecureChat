const $=s=>document.querySelector(s);
const notice=$("#report-notice"),panel=$("#report-panel"),form=$("#report-form"),submit=$("#report-submit");
function show(text,type=""){notice.textContent=text;notice.className="notice "+type;}
async function api(path,options={}){
 const response=await fetch(path,{method:options.method||"GET",credentials:"same-origin",cache:"no-store",headers:{"Accept":"application/json",...(options.body?{"Content-Type":"application/json"}:{})},...(options.body?{body:JSON.stringify(options.body)}:{})});
 const data=await response.json().catch(()=>({}));
 if(!response.ok){const message=data.error==="UNAUTHENTICATED"?"ログインが必要です。SecureChatにログインしてから報告してください。":data.error==="DATA_ENCRYPTION_NOT_CONFIGURED"?"保存データ暗号鍵が未設定のため、報告を安全に保存できません。管理者へ連絡してください。":data.error==="RATE_LIMITED"?"送信回数の上限です。15分ほど待ってから再試行してください。":data.error||"送信できませんでした。";throw new Error(message);}
 return data;
}
(async()=>{
 try{
  const me=await api("/api/auth/me");
  if(!me.authenticated){show("報告するにはログインしてください。","error");return;}
  panel.hidden=false;show("@"+me.user.userId+" として報告できます。","ok");
 }catch(e){show(e.message,"error");}
})();
form.addEventListener("submit",async e=>{
 e.preventDefault();submit.disabled=true;
 const body={category:$("#report-category").value,title:$("#report-title").value,description:$("#report-description").value,steps:$("#report-steps").value,expected:$("#report-expected").value,actual:$("#report-actual").value};
 try{await api("/api/bug-reports",{method:"POST",body});form.reset();show("報告を暗号化して送信しました。ご協力ありがとうございます。","ok");}
 catch(error){show(error.message,"error");}
 finally{submit.disabled=false;}
});
