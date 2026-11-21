import test from "node:test";
import { handleAdminFeatures } from "../worker/admin-features.js";
import assert from "node:assert/strict";
import {
  securityDiagnosticSchema,
  summarizeSecurityDiagnostics
} from "../worker/security-diagnostics.js";

class FakeStatement {
  constructor(db, sql) { this.db=db; this.sql=sql; this.values=[]; }
  bind(...values) { this.values=values; return this; }
  async first() {
    const sql=this.sql;
    if(sql.includes("PRAGMA quick_check")) {
      if(this.db.failQuickCheck)throw new Error("simulated quick_check failure");
      return {quick_check:"ok"};
    }
    if(sql.includes("SELECT 1 AS ok"))return {ok:1};
    if(sql.includes("name='d1_migrations'"))return {name:"d1_migrations"};
    if(sql.includes("FROM announcements WHERE encryption_version"))return {count:0};
    if(sql.includes("FROM admin_audit_logs WHERE details_json"))return {count:0};
    if(sql.includes("FROM bug_reports WHERE encrypted_payload"))return {count:0};
    if(sql.includes("FROM user_keys WHERE identity_signing_public_key"))return {count:0};
    if(sql.includes("FROM sessions WHERE expires_at"))return {count:0};
    if(sql.includes("FROM encrypted_messages WHERE expires_at"))return {count:0};
    if(sql.includes("FROM (SELECT user_a_id"))return {count:0};
    return null;
  }
  async all() {
    const sql=this.sql;
    if(sql.includes("AS key_version"))return {results:this.db.keyUsageRows};
    if(sql.includes("sqlite_master")&&sql.includes("type IN ('table','view','trigger')")) {
      const objects=[
        ...Object.keys(securityDiagnosticSchema.tables.reduce((a,t)=>(a[t]=true,a),{})).map(name=>({name,type:"table",sql:this.db.tableSql[name]||"CREATE TABLE "+name+" (id TEXT)"})),
        {name:"d1_migrations",type:"table",sql:"CREATE TABLE d1_migrations (name TEXT)"}
      ];
      if(this.db.extraObject)objects.push({name:this.db.extraObject,type:"table",sql:"CREATE TABLE "+this.db.extraObject+" (id TEXT)"});
      return {results:objects};
    }
    if(sql.includes("sqlite_master")&&sql.includes("type='table'")) {
      return {results:Object.keys(this.db.tableSql).map(name=>({name,type:"table",sql:this.db.tableSql[name]}))};
    }
    if(sql.includes("sqlite_master")&&sql.includes("type='index'")) {
      return {results:securityDiagnosticSchema.indexes.map(name=>({name}))};
    }
    if(sql.includes("PRAGMA table_info")) {
      const table=sql.match(/table_info\("([^"]+)"\)/)?.[1];
      let columns=securityDiagnosticSchema.tables.includes(table)
        ? this.db.columns[table]||[]
        : [];
      return {results:columns.map(name=>({name}))};
    }
    if(sql.includes("PRAGMA foreign_key_list")) {
      const table=sql.match(/foreign_key_list\("([^"]+)"\)/)?.[1];
      return {results:securityDiagnosticSchema.foreignKeys
        .filter(([fromTable])=>fromTable===table)
        .map(([,from,to,ref])=>({from,table:to,to:ref}))};
    }
    if(sql.includes("PRAGMA foreign_key_check"))return {results:[]};
    if(sql.includes("FROM d1_migrations")) {
      return {results:securityDiagnosticSchema.migrations.map(name=>({name}))};
    }
    if(sql.includes("FROM announcements WHERE encryption_version")||
       sql.includes("FROM admin_audit_logs WHERE details_json")||
       sql.includes("FROM bug_reports WHERE encrypted_payload"))return {results:[]};
    return {results:[]};
  }
}

class FakeDB {
  constructor({failQuickCheck=false,missingColumn=null,extraObject=null,keyUsageRows=[]}={}) {
    this.failQuickCheck=failQuickCheck;
    this.extraObject=extraObject;
    this.keyUsageRows=keyUsageRows;
    this.columns=Object.fromEntries(securityDiagnosticSchema.tables.map(table=>[table,[...knownColumns[table]]]));
    if(missingColumn) {
      const [table,column]=missingColumn;
      this.columns[table]=this.columns[table].filter(item=>item!==column);
    }
    this.tableSql={
      users:"CREATE TABLE users (id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE)",
      conversations:"CREATE TABLE conversations (id TEXT PRIMARY KEY, expires_in_seconds INTEGER CHECK (expires_in_seconds = 3600))",
      encrypted_messages:"CREATE TABLE encrypted_messages (id TEXT PRIMARY KEY, expires_at INTEGER CHECK (expires_at = created_at + 3600000))",
      contact_invitations:"CREATE TABLE contact_invitations (id TEXT PRIMARY KEY, inviter_attempts INTEGER CHECK (inviter_attempts BETWEEN 0 AND 5), invitee_attempts INTEGER CHECK (invitee_attempts BETWEEN 0 AND 5))",
      conversation_pairs:"CREATE TABLE conversation_pairs (user_a_id TEXT, user_b_id TEXT, CHECK (user_a_id < user_b_id))"
    };
    for(const table of securityDiagnosticSchema.tables) {
      if(!this.tableSql[table])this.tableSql[table]="CREATE TABLE "+table+" (id TEXT)";
    }
  }
  prepare(sql) { return new FakeStatement(this,sql); }
}
const knownColumns = {
  users:["id","user_id","password_salt","password_hash","password_iterations","created_at","last_login_at","is_admin","password_changed_at"],
  sessions:["token_hash","user_id","expires_at","created_at"],
  user_keys:["user_id","identity_public_key","signed_prekey","signed_prekey_signature","key_version","updated_at","identity_signing_public_key","identity_key_signature"],
  contacts:["owner_user_id","contact_user_id","created_at"],
  conversations:["id","created_by","created_at","expires_in_seconds"],
  conversation_members:["conversation_id","user_id","joined_at"],
  encrypted_messages:["id","conversation_id","sender_user_id","ciphertext","nonce","algorithm","created_at","expires_at"],
  conversation_keys:["conversation_id","user_id","key_envelope","created_at"],
  verified_contact_pairs:["user_a_id","user_b_id","verified_at"],
  contact_invitations:["id","inviter_user_id","invitee_user_id","inviter_code_hash","inviter_code_expires_at","inviter_attempts","invitee_code_hash","invitee_code_expires_at","invitee_attempts","invitee_verified_at","inviter_verified_at","expires_at","created_at"],
  registration_invites:["id","created_by_user_id","code_hash","expires_at","created_at","used_at"],
  rate_limit_buckets:["bucket_key","window_started_at","request_count","expires_at"],
  announcements:["id","title","body","published","created_by_user_id","created_at","updated_at","published_at","title_ciphertext","body_ciphertext","encryption_version","expires_at"],
  admin_audit_logs:["id","admin_user_id","action","target_user_id","details_json","created_at"],
  bug_reports:["id","reporter_user_id","encrypted_payload","status","created_at","updated_at","resolved_at"],
  conversation_pairs:["user_a_id","user_b_id","conversation_id","created_at"]
};
function environment(options) {
  return {
    DB:new FakeDB(options),
    APP_DATA_ENCRYPTION_KEY:"x".repeat(32),
    CONTACT_OTP_PEPPER:"y".repeat(32)
  };
}

test("key rotation remains warning until old ciphertext is migrated", async () => {
  const env=environment({keyUsageRows:[
    {key_version:1,record_count:2},
    {key_version:2,record_count:8}
  ]});
  env.APP_DATA_ENCRYPTION_KEY_V2="z".repeat(32);
  env.APP_DATA_ENCRYPTION_ACTIVE_VERSION="2";
  const result=await summarizeSecurityDiagnostics(env);
  const check=result.checks.find(item=>item.id==="key-rotation");
  assert.equal(check.status,"warning");
  assert.match(check.detail,/2 件残っています/);
});

test("key rotation is critical when old ciphertext remains but its old key is missing", async () => {
  const env=environment({keyUsageRows:[{key_version:1,record_count:1}]});
  delete env.APP_DATA_ENCRYPTION_KEY;
  env.APP_DATA_ENCRYPTION_KEY_V2="z".repeat(32);
  env.APP_DATA_ENCRYPTION_ACTIVE_VERSION="2";
  const result=await summarizeSecurityDiagnostics(env);
  assert.equal(result.checks.find(item=>item.id==="key-rotation").status,"critical");
});

test("key rotation passes only after all encrypted rows use the active generation", async () => {
  const env=environment({keyUsageRows:[{key_version:2,record_count:12}]});
  env.APP_DATA_ENCRYPTION_KEY_V2="z".repeat(32);
  env.APP_DATA_ENCRYPTION_ACTIVE_VERSION="2";
  const result=await summarizeSecurityDiagnostics(env);
  assert.equal(result.checks.find(item=>item.id==="key-rotation").status,"ok");
});

test("forward secrecy and admin passkeys remain explicitly incomplete until implemented", async () => {
  const result=await summarizeSecurityDiagnostics(environment());
  assert.equal(result.checks.find(item=>item.id==="forward-secrecy").status,"critical");
  assert.equal(result.checks.find(item=>item.id==="passkeys").status,"warning");
  const logs=result.checks.find(item=>item.id==="cloudflare-logs");
  assert.equal(logs.status,"warning");
  assert.equal(logs.complete,false);
});

test("diagnostics cover SQL schema, indexes, migration history and runtime integrity", async () => {
  const result=await summarizeSecurityDiagnostics(environment());
  const ids=new Set(result.checks.map(check=>check.id));
  for(const id of [
    "db-quick-check","db-foreign-key-check","schema-inventory","schema-unexpected-objects","schema-constraints",
    "schema-indexes","schema-foreign-keys","schema-migrations","message-retention",
    "identity-key-proofs","external-engines"
  ])assert.ok(ids.has(id),`Missing diagnostic: ${id}`);
  assert.equal(result.checks.find(check=>check.id==="schema-inventory").status,"ok");
  assert.equal(result.checks.find(check=>check.id==="schema-migrations").status,"ok");
  assert.ok(result.coverage.total>=20);
});

test("a failed database check is reported and does not suppress later checks", async () => {
  const result=await summarizeSecurityDiagnostics(environment({failQuickCheck:true}));
  assert.equal(result.overall,"error");
  assert.equal(result.checks.find(check=>check.id==="db-quick-check").status,"error");
  assert.equal(result.checks.find(check=>check.id==="schema-inventory").status,"ok");
  assert.ok(result.coverage.notCompleted>=1);
});

test("missing required D1 columns are critical rather than passing", async () => {
  const result=await summarizeSecurityDiagnostics(environment({missingColumn:["user_keys","identity_key_signature"]}));
  assert.equal(result.checks.find(check=>check.id==="schema-inventory").status,"critical");
});

test("external scan results are not treated as passing when no GitHub token is configured", async () => {
  const result=await summarizeSecurityDiagnostics(environment());
  const external=result.checks.find(check=>check.id==="external-engines");
  assert.equal(external.status,"warning");
  assert.equal(external.complete,false);
  assert.notEqual(result.overall,"ok");
});


test("the admin endpoint continues reporting secret and scanner checks when D1 is unavailable", async () => {
  const env = {
    DB: { prepare() { throw new Error("simulated D1 outage"); } },
    APP_DATA_ENCRYPTION_KEY: "x".repeat(32),
    CONTACT_OTP_PEPPER: "y".repeat(32)
  };
  const admin = {
    id: "admin-id",
    user_id: "admin",
    is_admin: 1,
    password_changed_at: Date.now(),
    created_at: Date.now()
  };
  const request = new Request("https://securechat.example/api/admin/security-check", { method: "GET" });
  const response = await handleAdminFeatures(request, env, {
    url: new URL(request.url),
    sameOrigin: () => true,
    getSession: async () => admin,
    readCookie: () => "session",
    checkRateLimit: async () => true
  });
  assert.equal(response.status, 200);
  const result = await response.json();
  const ids = new Set(result.checks.map(check => check.id));
  assert.ok(ids.has("db-quick-check"));
  assert.ok(ids.has("schema-inventory"));
  assert.ok(ids.has("external-engines"));
  assert.equal(result.checks.find(check => check.id === "db-quick-check").status, "error");
  assert.equal(result.checks.find(check => check.id === "external-engines").complete, false);
  assert.ok(result.coverage.notCompleted > 0);
});


test("unexpected database objects are visible as a warning", async () => {
  const result=await summarizeSecurityDiagnostics(environment({extraObject:"legacy_debug_table"}));
  const check=result.checks.find(item=>item.id==="schema-unexpected-objects");
  assert.equal(check.status,"warning");
  assert.match(check.detail,/legacy_debug_table/);
});
