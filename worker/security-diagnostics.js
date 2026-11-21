import { dataKeyStatus } from "./data-crypto.js";

const EXPECTED_TABLES = {
  users: ["id","user_id","password_salt","password_hash","password_iterations","created_at","last_login_at","is_admin","password_changed_at"],
  sessions: ["token_hash","user_id","expires_at","created_at"],
  user_keys: ["user_id","identity_public_key","signed_prekey","signed_prekey_signature","key_version","updated_at","identity_signing_public_key","identity_key_signature"],
  contacts: ["owner_user_id","contact_user_id","created_at"],
  conversations: ["id","created_by","created_at","expires_in_seconds"],
  conversation_members: ["conversation_id","user_id","joined_at"],
  encrypted_messages: ["id","conversation_id","sender_user_id","ciphertext","nonce","algorithm","created_at","expires_at"],
  conversation_keys: ["conversation_id","user_id","key_envelope","created_at"],
  verified_contact_pairs: ["user_a_id","user_b_id","verified_at"],
  contact_invitations: ["id","inviter_user_id","invitee_user_id","inviter_code_hash","inviter_code_expires_at","inviter_attempts","invitee_code_hash","invitee_code_expires_at","invitee_attempts","invitee_verified_at","inviter_verified_at","expires_at","created_at"],
  registration_invites: ["id","created_by_user_id","code_hash","expires_at","created_at","used_at"],
  rate_limit_buckets: ["bucket_key","window_started_at","request_count","expires_at"],
  announcements: ["id","title","body","published","created_by_user_id","created_at","updated_at","published_at","title_ciphertext","body_ciphertext","encryption_version","expires_at"],
  admin_audit_logs: ["id","admin_user_id","action","target_user_id","details_json","created_at"],
  bug_reports: ["id","reporter_user_id","encrypted_payload","status","created_at","updated_at","resolved_at"],
  conversation_pairs: ["user_a_id","user_b_id","conversation_id","created_at"]
};

const EXPECTED_INDEXES = [
  "sessions_user_id_idx","sessions_expires_at_idx",
  "conversations_member_lookup_idx","encrypted_messages_expiry_idx","encrypted_messages_conversation_idx",
  "contacts_lookup_idx","conversation_keys_user_idx",
  "contact_invitations_inviter_idx","contact_invitations_invitee_idx",
  "registration_invites_creator_idx","registration_invites_expiry_idx",
  "rate_limit_buckets_expiry_idx","announcements_published_idx",
  "admin_audit_logs_created_at_idx","admin_audit_logs_admin_user_idx",
  "announcements_expiry_idx","bug_reports_status_created_idx","bug_reports_reporter_idx",
  "users_created_at_admin_idx","users_last_login_idx"
];

const EXPECTED_MIGRATIONS = [
  "0001_initial.sql","0002_private_chat_e2ee.sql","0003_mutual_otp_contacts.sql",
  "0004_registration_invites.sql","0005_persistent_rate_limits.sql","0006_admin_console.sql",
  "0007_admin_password_rotation.sql","0008_admin_security_reports.sql",
  "0009_signed_identity_keys.sql","0010_unique_conversation_pairs.sql"
];

const EXPECTED_FOREIGN_KEYS = [
  ["sessions","user_id","users","id"],
  ["user_keys","user_id","users","id"],
  ["contacts","owner_user_id","users","id"],["contacts","contact_user_id","users","id"],
  ["conversations","created_by","users","id"],
  ["conversation_members","conversation_id","conversations","id"],["conversation_members","user_id","users","id"],
  ["encrypted_messages","conversation_id","conversations","id"],["encrypted_messages","sender_user_id","users","id"],
  ["conversation_keys","conversation_id","conversations","id"],["conversation_keys","user_id","users","id"],
  ["verified_contact_pairs","user_a_id","users","id"],["verified_contact_pairs","user_b_id","users","id"],
  ["contact_invitations","inviter_user_id","users","id"],["contact_invitations","invitee_user_id","users","id"],
  ["registration_invites","created_by_user_id","users","id"],
  ["bug_reports","reporter_user_id","users","id"],
  ["conversation_pairs","user_a_id","users","id"],["conversation_pairs","user_b_id","users","id"],
  ["conversation_pairs","conversation_id","conversations","id"]
];

function add(checks,id,label,status,detail,extra={}) {
  checks.push({id,label,status,detail,...extra});
}
async function runIsolated(checks,id,label,fn) {
  try {
    const result=await fn();
    add(checks,id,label,result.status,result.detail,result.extra||{});
  } catch(error) {
    add(checks,id,label,"error",
      "検査自体を完了できませんでした。安全とは判定していません。 ("+String(error?.message||error).slice(0,180)+")",
      {complete:false});
  }
}
function rows(result) { return Array.isArray(result?.results)?result.results:[]; }
function firstValue(record) { return record && Object.values(record)[0]; }
function summarize(checks) {
  const statuses=checks.map(check=>check.status);
  const overall=statuses.includes("error")?"error":
    statuses.includes("critical")?"critical":
    statuses.includes("warning")?"warning":"ok";
  return {
    overall,
    checkedAt:Date.now(),
    coverage:{total:checks.length,completed:checks.filter(x=>x.complete!==false).length,notCompleted:checks.filter(x=>x.complete===false).length},
    checks
  };
}

async function checkSchema(env,checks) {
  await runIsolated(checks,"schema-inventory","D1テーブル・カラム構造",async()=>{
    const objects=rows(await env.DB.prepare(
      "SELECT name,type,sql FROM sqlite_master WHERE type IN ('table','view','trigger') AND name NOT LIKE 'sqlite_%'"
    ).all());
    const tableNames=new Set(objects.filter(x=>x.type==="table").map(x=>x.name));
    const missingTables=[],missingColumns=[];
    for(const [table,columns] of Object.entries(EXPECTED_TABLES)) {
      if(!tableNames.has(table)){missingTables.push(table);continue;}
      const info=rows(await env.DB.prepare('PRAGMA table_info("'+table+'")').all());
      const names=new Set(info.map(x=>x.name));
      for(const column of columns)if(!names.has(column))missingColumns.push(table+"."+column);
    }
    if(missingTables.length||missingColumns.length) {
      return {status:"critical",detail:"スキーマ差分を検出しました。欠落テーブル: "+(missingTables.join(", ")||"なし")+"。欠落カラム: "+(missingColumns.join(", ")||"なし")+"。マイグレーション状態とDB接続先を確認してください。"};
    }
    return {status:"ok",detail:"必須 "+Object.keys(EXPECTED_TABLES).length+" テーブルと定義済み必須カラムをすべて確認しました。追加テーブル: "+Math.max(0,tableNames.size-Object.keys(EXPECTED_TABLES).length)+"。"};
  });

  await runIsolated(checks,"schema-constraints","SQL制約・データ保持ルール",async()=>{
    const objects=rows(await env.DB.prepare("SELECT name,type,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all());
    const definitions=new Map(objects.map(item=>[item.name,String(item.sql||"").toLowerCase().replace(/[ \t\r\n"`\\[\\]]/g,"")]));
    const requirements=[
      ["users","user_idtextnotnullunique"],
      ["conversations","check(expires_in_seconds=3600)"],
      ["encrypted_messages","check(expires_at=created_at+3600000)"],
      ["contact_invitations","check(inviter_attemptsbetween0and5)"],
      ["contact_invitations","check(invitee_attemptsbetween0and5)"],
      ["conversation_pairs","check(user_a_id<user_b_id)"]
    ];
    const missing=requirements.filter(([table,fragment])=>!definitions.get(table)?.includes(fragment));
    return missing.length
      ? {status:"critical",detail:"必須SQL制約が見つかりません: "+missing.map(([table,fragment])=>table+" ("+fragment+")").join(", ")}
      : {status:"ok",detail:"ユーザーID一意性、保存期限、OTP試行回数、会話ペア順序のSQL制約を確認しました。"};
  });

  await runIsolated(checks,"schema-indexes","SQLインデックス構成",async()=>{
    const result=rows(await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'").all());
    const found=new Set(result.map(x=>x.name));
    const missing=EXPECTED_INDEXES.filter(name=>!found.has(name));
    return missing.length
      ? {status:"warning",detail:"性能・検索範囲を支える必須インデックスが "+missing.length+" 件不足しています: "+missing.join(", ")}
      : {status:"ok",detail:"定義済み必須インデックス "+EXPECTED_INDEXES.length+" 件を確認しました。"};
  });

  await runIsolated(checks,"schema-foreign-keys","外部キー制約の定義",async()=>{
    const cache=new Map();
    const missing=[];
    for(const [table,from,to,ref] of EXPECTED_FOREIGN_KEYS) {
      if(!cache.has(table)) {
        const result=rows(await env.DB.prepare('PRAGMA foreign_key_list("'+table+'")').all());
        cache.set(table,result);
      }
      if(!cache.get(table).some(x=>x.from===from&&x.table===to&&x.to===ref))missing.push(table+"."+from+" → "+to+"."+ref);
    }
    return missing.length
      ? {status:"critical",detail:"必要な外部キー制約が不足しています: "+missing.join("; ")}
      : {status:"ok",detail:"必須外部キー制約 "+EXPECTED_FOREIGN_KEYS.length+" 件を確認しました。"};
  });

  await runIsolated(checks,"schema-migrations","D1マイグレーション履歴",async()=>{
    const exists=await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='d1_migrations'").first();
    if(!exists)return {status:"error",detail:"d1_migrations が存在せず、適用済みマイグレーションを検証できません。手動変更DBの場合も履歴を整備するまで未判定です。",extra:{complete:false}};
    const applied=rows(await env.DB.prepare("SELECT name FROM d1_migrations").all()).map(x=>String(x.name||"").split("/").pop());
    const appliedNormalized=new Set(applied.map(x=>x.replace(/\.sql$/,"")));
    const missing=EXPECTED_MIGRATIONS.filter(name=>!appliedNormalized.has(name.replace(/\.sql$/,"")));
    return missing.length
      ? {status:"critical",detail:"未適用の必須マイグレーション: "+missing.join(", ")}
      : {status:"ok",detail:"必須マイグレーション "+EXPECTED_MIGRATIONS.length+" 件が適用済みです。適用履歴 "+applied.length+" 件。"};
  });
}

async function checkDatabaseIntegrity(env,checks) {
  await runIsolated(checks,"db-quick-check","D1データベース整合性",async()=>{
    const result=await env.DB.prepare("PRAGMA quick_check").first();
    const value=String(firstValue(result)||"").toLowerCase();
    return value==="ok"
      ? {status:"ok",detail:"SQLite quick_check は OK を返しました。"}
      : {status:"critical",detail:"quick_check が異常を返しました: "+value.slice(0,400)};
  });
  await runIsolated(checks,"db-foreign-key-check","外部キー参照整合性",async()=>{
    const result=rows(await env.DB.prepare("PRAGMA foreign_key_check").all());
    return result.length
      ? {status:"critical",detail:"外部キー違反を "+result.length+" 件検出しました。先頭: "+JSON.stringify(result.slice(0,3))}
      : {status:"ok",detail:"外部キー違反は検出されませんでした。"};
  });
  await runIsolated(checks,"db-query-health","D1読み書きAPI",async()=>{
    const result=await env.DB.prepare("SELECT 1 AS ok").first();
    return Number(result?.ok)===1
      ? {status:"ok",detail:"D1の実行クエリを確認しました。"}
      : {status:"error",detail:"D1の応答が想定外です。",extra:{complete:false}};
  });
}

async function checkDataState(env,checks,keyStatus) {
  await runIsolated(checks,"sensitive-data-migration","機密データ暗号化状態",async()=>{
    const prefix="enc:v"+keyStatus.activeVersion+":%";
    const [notices,logs,reports]=await Promise.all([
      env.DB.prepare("SELECT COUNT(*) AS count FROM announcements WHERE encryption_version=0 OR title_ciphertext IS NULL OR body_ciphertext IS NULL OR title_ciphertext NOT LIKE ? OR body_ciphertext NOT LIKE ?").bind(prefix,prefix).first(),
      env.DB.prepare("SELECT COUNT(*) AS count FROM admin_audit_logs WHERE details_json NOT LIKE ?").bind(prefix).first(),
      env.DB.prepare("SELECT COUNT(*) AS count FROM bug_reports WHERE encrypted_payload NOT LIKE ?").bind(prefix).first()
    ]);
    const n=Number(notices?.count||0),l=Number(logs?.count||0),r=Number(reports?.count||0);
    const count=n+l+r;
    return count
      ? {status:"warning",detail:"暗号化移行が必要な行: お知らせ "+n+" 件、監査ログ "+l+" 件、バグ報告 "+r+" 件。"}
      : {status:"ok",detail:"お知らせ・監査ログ・バグ報告の機密データは現行鍵形式です。"};
  });

  await runIsolated(checks,"identity-key-proofs","署名付きユーザー公開鍵",async()=>{
    const r=await env.DB.prepare("SELECT COUNT(*) AS count FROM user_keys WHERE identity_signing_public_key IS NULL OR TRIM(identity_signing_public_key)='' OR identity_key_signature IS NULL OR TRIM(identity_key_signature)=''").first();
    const count=Number(r?.count||0);
    return count
      ? {status:"critical",detail:"署名証明が未登録の公開鍵が "+count+" 件あります。該当ユーザーに最新版で再登録してもらってください。"}
      : {status:"ok",detail:"全登録公開鍵にアカウントIDとの署名証明があります。初回指紋照合は別経路で必要です。"};
  });

  await runIsolated(checks,"expired-sessions","期限切れセッションの清掃",async()=>{
    const r=await env.DB.prepare("SELECT COUNT(*) AS count FROM sessions WHERE expires_at<=?").bind(Date.now()).first();
    const count=Number(r?.count||0);
    return count
      ? {status:"warning",detail:"期限切れセッションが "+count+" 件残っています。Cron実行・削除処理を確認してください。"}
      : {status:"ok",detail:"期限切れセッションは残っていません。"};
  });

  await runIsolated(checks,"message-retention","メッセージ保存期限",async()=>{
    const r=await env.DB.prepare("SELECT COUNT(*) AS count FROM encrypted_messages WHERE expires_at<>created_at+3600000 OR expires_at<=created_at").first();
    const count=Number(r?.count||0);
    return count
      ? {status:"critical",detail:"1時間の保存期限ルールに違反するメッセージが "+count+" 件あります。"}
      : {status:"ok",detail:"保存中メッセージの期限は作成時刻から1時間に制限されています。"};
  });

  await runIsolated(checks,"conversation-pair-integrity","個別チャットの一意性",async()=>{
    const r=await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM (SELECT user_a_id,user_b_id,COUNT(*) AS n FROM conversation_pairs GROUP BY user_a_id,user_b_id HAVING n>1)"
    ).first();
    const count=Number(r?.count||0);
    return count
      ? {status:"critical",detail:"同じユーザー組の会話マッピング重複が "+count+" 件あります。"}
      : {status:"ok",detail:"同じユーザー組の会話が重複しないことを確認しました。"};
  });
}

async function checkExternalEngines(env,checks) {
  const token=env.SECURITY_SCAN_GITHUB_TOKEN;
  if(typeof token!=="string"||token.length<20) {
    add(checks,"external-engines","外部セキュリティエンジン連携","warning",
      "Semgrep・SQLFluff・OWASP ZAP を GitHub Actions で実行します。管理画面で最新結果を照合するには Worker Secret SECURITY_SCAN_GITHUB_TOKEN（対象リポジトリの Actions: read）が必要です。未連携・未実行は安全と判定しません。",
      {complete:false,url:"https://github.com/hugohinoto/SecureChat/actions/workflows/security-scan.yml"});
    return;
  }
  try {
    const headers={
      Accept:"application/vnd.github+json",
      Authorization:"Bearer "+token,
      "X-GitHub-Api-Version":"2022-11-28",
      "User-Agent":"SecureChat-Security-Diagnostics"
    };
    const runResponse=await fetch(
      "https://api.github.com/repos/hugohinoto/SecureChat/actions/workflows/security-scan.yml/runs?branch=main&per_page=10",
      {headers,signal:AbortSignal.timeout(6000)}
    );
    if(!runResponse.ok)throw new Error("GitHub Actions API HTTP "+runResponse.status);
    const payload=await runResponse.json();
    const latest=(payload.workflow_runs||[]).find(run=>["push","schedule","workflow_dispatch"].includes(run.event));
    if(!latest) {
      add(checks,"external-engines","外部セキュリティエンジン連携","warning",
        "main ブランチのスキャン実行結果がありません。安全とは判定していません。",
        {complete:false,url:"https://github.com/hugohinoto/SecureChat/actions/workflows/security-scan.yml"});
      return;
    }
    const jobsResponse=await fetch(latest.jobs_url,{headers,signal:AbortSignal.timeout(6000)});
    if(!jobsResponse.ok)throw new Error("GitHub Actions jobs API HTTP "+jobsResponse.status);
    const jobsPayload=await jobsResponse.json(),jobs=jobsPayload.jobs||[];
    const expected=[
      ["semgrep","Semgrep SAST"],
      ["sqlfluff","SQLFluff SQL parse"],
      ["zap","OWASP ZAP passive DAST"]
    ];
    for(const [jobName,label] of expected) {
      const job=jobs.find(item=>item.name.toLowerCase().includes(jobName));
      if(!job) {
        add(checks,"engine-"+jobName,label,"warning",
          "最新スキャンにこのエンジンの結果がありません。未実行を安全とは判定しません。",
          {complete:false,url:latest.html_url});
        continue;
      }
      const status=job.status==="completed"
        ? (job.conclusion==="success"?"ok":job.conclusion==="failure"?"critical":"warning")
        : "warning";
      add(checks,"engine-"+jobName,label,status,
        "実行: "+job.status+" / 結果: "+(job.conclusion||"未完了")+" / "+new Date(job.started_at||latest.created_at).toLocaleString("ja-JP"),
        {complete:job.status==="completed",url:latest.html_url});
    }
  } catch(error) {
    add(checks,"external-engines","外部セキュリティエンジン連携","error",
      "外部スキャンの結果を取得できませんでした。通信・トークン権限・GitHub Actionsの状態を確認してください。安全とは判定していません。 ("+String(error?.message||error).slice(0,160)+")",
      {complete:false,url:"https://github.com/hugohinoto/SecureChat/actions/workflows/security-scan.yml"});
  }
}

export async function summarizeSecurityDiagnostics(env) {
  const checks=[];
  let keyStatus={activeVersion:1,configuredVersions:[],activeKeyReady:false};
  try { keyStatus=dataKeyStatus(env); } catch {}
  add(checks,"data-key","保存データ暗号鍵",keyStatus.activeKeyReady?"ok":"error",
    keyStatus.activeKeyReady
      ? "現行鍵 v"+keyStatus.activeVersion+" を確認しました。設定済み世代: "+keyStatus.configuredVersions.join(", ")+"."
      : "現行鍵 v"+keyStatus.activeVersion+" が未設定、または32バイト未満です。");
  const otpReady=typeof env.CONTACT_OTP_PEPPER==="string"&&env.CONTACT_OTP_PEPPER.length>=32;
  add(checks,"otp-key","OTP秘密値",otpReady?"ok":"error",
    otpReady?"CONTACT_OTP_PEPPER を確認しました。":"CONTACT_OTP_PEPPER が未設定、または短すぎます。");
  await checkDatabaseIntegrity(env,checks);
  await checkSchema(env,checks);
  await checkDataState(env,checks,keyStatus);
  add(checks,"key-rotation","暗号鍵ローテーション",keyStatus.activeKeyReady&&keyStatus.configuredVersions.length>=2?"ok":keyStatus.activeKeyReady?"warning":"error",
    keyStatus.activeKeyReady
      ?"現行鍵 v"+keyStatus.activeVersion+"。登録済み鍵世代: "+keyStatus.configuredVersions.join(", ")+"。移行完了前に旧鍵を削除しないでください。"
      :"現行鍵が未設定です。");
  add(checks,"forward-secrecy","前方秘匿性","critical","Double Ratchet 等による鍵更新・前方秘匿性は未実装です。");
  add(checks,"passkeys","管理者パスキー","warning","現状はパスワード認証です。パスキーと予備キーは未実装です。");
  add(checks,"cloudflare-logs","Cloudflare Invocation Logs","warning","プラットフォームログの保存・閲覧権限はこの診断から検証できません。Workerログに秘密情報やメッセージ本文を出力しない運用が必要です。",{complete:false});
  await checkExternalEngines(env,checks);
  return summarize(checks);
}

export const securityDiagnosticSchema = {
  tables:Object.keys(EXPECTED_TABLES),
  indexes:EXPECTED_INDEXES,
  migrations:EXPECTED_MIGRATIONS,
  foreignKeys:EXPECTED_FOREIGN_KEYS
};
