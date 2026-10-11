import assert from "node:assert/strict";
import {randomBytes,randomUUID} from "node:crypto";
import {after,before,beforeEach,describe,it} from "node:test";
import type {FastifyInstance} from "fastify";
import {buildApp} from "../../src/api/app.js";
import {buildRuntime,type ApplicationRuntime} from "../../src/api/services.js";
import {loadConfig} from "../../src/config/env.js";
import {PostgresDatabase} from "../../src/infrastructure/postgres/database.js";
import {PostgresControlPlaneRepository} from "../../src/infrastructure/postgres/postgres-control-plane-repository.js";
import {PostgresControlCentreRepository} from "../../src/infrastructure/postgres/postgres-control-centre-repository.js";
import {Argon2PasswordOperations} from "../../src/authentication/adapters/argon2-password-operations.js";
import {WorkloadAdministration,workloadCreateSchema} from "../../src/control-plane/application/workload-administration.js";
import {MANAGED_WORKLOAD_CAPABILITIES} from "../../src/control-plane/models.js";
import {SessionId} from "../../src/sessions/domain/session-id.js";
import {executeOperatorRequest} from "../../scripts/manage-product-workload-helpers.js";
import {syntheticManagementEnabled} from "../../src/control-plane/application/identity-management.js";
const url=process.env.POSTGRES_WORKLOAD_TEST_DATABASE_URL;
const password="Synthetic-workload-test-password-123!";
const generated=()=>randomBytes(32).toString("base64url");
const reason="Synthetic approved integration validation";

describe("workload administration configuration and request boundary",()=>{
  it("is disabled by default and rejects malformed flag values",()=>{
    assert.equal(loadConfig({}).IDENTITY_WORKLOAD_ADMINISTRATION_ENABLED,false);
    assert.throws(()=>loadConfig({IDENTITY_WORKLOAD_ADMINISTRATION_ENABLED:"1"}));
  });
  it("requires canonical high-entropy-format secrets and report-only unique scopes",()=>{
    const input={requestId:randomUUID(),id:"test-backend",productId:"grocery-master",secret:generated(),capabilities:["human.participation.register"],reason};
    assert.equal(workloadCreateSchema.safeParse(input).success,true);
    for(const change of [{secret:"A".repeat(43)},{secret:"human-password"},{capabilities:["team.manage"]},{capabilities:["identity.dependencies.report"]},{capabilities:["human.participation.register","human.participation.register"]},{capabilities:[]},{humanIdentityId:randomUUID()},{status:"active"}])assert.equal(workloadCreateSchema.safeParse({...input,...change}).success,false);
  });
});

describe("audited scoped workload administration on isolated PostgreSQL",{skip:!url},()=>{
  let db:PostgresDatabase,second:PostgresDatabase,runtime:ApplicationRuntime,app:FastifyInstance,plane:PostgresControlPlaneRepository;
  let admin:string,bearer:string,adminRenewalToken:string,otherAdmin:string,otherBearer:string,human:string,humanBearer:string;
  const ops=new Argon2PasswordOperations({memoryCost:8192,timeCost:2,parallelism:1});
  const service=()=>runtime.services.administration.workloads!;
  const token=()=>SessionId.from(bearer);
  const input=(id="grocery-reporting",capabilities:readonly string[]=MANAGED_WORKLOAD_CAPABILITIES)=>({requestId:randomUUID(),id,productId:"grocery-master",secret:generated(),capabilities,reason});
  const request=(operation:string,payload:Record<string,unknown>,session=bearer)=>app.inject({method:"POST",url:`/administration/platform/workloads/${operation}`,payload,headers:session?{authorization:`Bearer ${session}`}:{}});
  const reporting=(id:string,secret:string,session=humanBearer)=>app.inject({method:"POST",url:"/control/human-participation",payload:{},headers:{authorization:`Bearer ${session}`,"x-gama-workload-id":id,"x-gama-workload-secret":secret}});
  const context=(id:string,secret:string)=>app.inject({method:"GET",url:"/control/workload-context",headers:{"x-gama-workload-id":id,"x-gama-workload-secret":secret}});
  const protectedFingerprint=async()=>{
    const result:Record<string,unknown>={};for(const table of ["human_identities","credentials","federated_identities","sessions","platform_administration_memberships","tenant_memberships","product_entitlements","product_participations","tenants","product_workloads"]){result[table]=(await db.query(`SELECT count(*)::int AS count,md5(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text) AS fingerprint FROM ${table} t`)).rows[0];}return result;
  };
  before(async()=>{
    assert.ok(syntheticManagementEnabled({NODE_ENV:"test",REPOSITORY_MODE:"postgres",DATABASE_URL:url!}),"Only separate local synthetic *_management_test databases are accepted");
    db=new PostgresDatabase(url!);second=new PostgresDatabase(url!);
    runtime=await buildRuntime(loadConfig({NODE_ENV:"test",REPOSITORY_MODE:"postgres",DATABASE_URL:url!,LOG_LEVEL:"silent",PASSWORD_HASH_MEMORY_KIB:"8192",PASSWORD_HASH_ITERATIONS:"2",IDENTITY_WORKLOAD_ADMINISTRATION_ENABLED:"true"}));
    app=buildApp(runtime.services,runtime.databaseHealth);plane=new PostgresControlPlaneRepository(db);
  });
  after(async()=>{await app?.close();await runtime?.close();await db?.close();await second?.close();});
  beforeEach(async()=>{
    await db.query("TRUNCATE human_identities,registered_products,tenants,platform_audit_events CASCADE");
    const a=await runtime.services.register.execute({email:"admin@workload.synthetic.example",password});admin=a.humanIdentityId;bearer=a.session.sessionId;adminRenewalToken=a.session.renewalToken;await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin,"synthetic-fixture");
    const o=await runtime.services.register.execute({email:"other-admin@workload.synthetic.example",password});otherAdmin=o.humanIdentityId;otherBearer=o.session.sessionId;await runtime.platformAdministrationProvisioning.bootstrapAdministrator(otherAdmin,"synthetic-fixture");
    const h=await runtime.services.register.execute({email:"human@workload.synthetic.example",password});human=h.humanIdentityId;humanBearer=h.session.sessionId;
    await plane.saveProduct({id:"grocery-master",displayName:"Grocery synthetic",status:"active"});await plane.saveProduct({id:"cashcast",displayName:"CashCast synthetic",status:"active"});
  });
  it("creates, inspects, rotates and revokes only one managed credential with immutable product binding and preserved account projections",async()=>{
    const before=await protectedFingerprint(),c=input();
    const created=await request("create",c);assert.equal(created.statusCode,200);assert.equal(created.headers["cache-control"],"no-store");assert.equal(created.json().workload.revision,1);
    const inspect=await request("inspect",{id:c.id});assert.equal(inspect.json().workloads.length,1);assert.equal(inspect.json().workloads[0].productId,"grocery-master");
    assert.deepEqual(await runtime.controlPlane.authenticateWorkload(c.id,c.secret,"human.participation.register"),{workloadId:c.id,productId:"grocery-master"});
    const next=generated(),rotate={requestId:randomUUID(),id:c.id,expectedRevision:1,secret:next,reason};
    const r=await request("rotate",rotate);assert.equal(r.statusCode,200);assert.equal(r.json().workload.revision,2);assert.equal(await runtime.controlPlane.authenticateWorkload(c.id,c.secret,"workload.context.read"),null);assert.ok(await runtime.controlPlane.authenticateWorkload(c.id,next,"workload.context.read"));
    const revoked=await request("revoke",{requestId:randomUUID(),id:c.id,expectedRevision:2,reason});assert.equal(revoked.statusCode,200);assert.equal(revoked.json().workload.status,"retired");assert.equal(await runtime.controlPlane.authenticateWorkload(c.id,next,"workload.context.read"),null);
    assert.deepEqual(await protectedFingerprint(),before);
    const events=await db.query("SELECT event_type,event_data FROM platform_audit_events WHERE event_type LIKE 'workload.managed.%' ORDER BY occurred_at,id");assert.equal(events.rowCount,4);assert.ok(events.rows.some(row=>row.event_type==="workload.managed.rotated"));
    for(const raw of [created.body,inspect.body,r.body,revoked.body,JSON.stringify(events.rows)]){assert.ok(!raw.includes(c.secret));assert.ok(!raw.includes(next));assert.ok(!raw.includes("secretHash"));assert.ok(!raw.includes("$argon2"));}
  });
  it("binds idempotency to actor and complete command and never replays secrets or previous hashes",async()=>{
    const c=input();await service().create(token(),c);assert.equal((await service().create(token(),c)).replayed,true);
    for(const change of [{secret:generated()},{productId:"cashcast"},{reason:"Different approved reason"},{capabilities:["human.participation.register"]}])await assert.rejects(service().create(token(),{...c,...change}),{code:"IDEMPOTENCY_KEY_REUSED"});
    await assert.rejects(service().create(SessionId.from(otherBearer),c),{code:"IDEMPOTENCY_KEY_REUSED"});
    const r={requestId:randomUUID(),id:c.id,expectedRevision:1,secret:generated(),reason};await service().rotate(token(),r);const hash=(await db.query("SELECT secret_hash FROM managed_product_workloads WHERE id=$1",[c.id])).rows[0]!.secret_hash;
    assert.equal((await service().rotate(token(),r)).replayed,true);assert.equal((await db.query("SELECT secret_hash FROM managed_product_workloads WHERE id=$1",[c.id])).rows[0]!.secret_hash,hash);
    const z={requestId:randomUUID(),id:c.id,expectedRevision:2,reason};await service().revoke(token(),z);assert.equal((await service().revoke(token(),z)).replayed,true);
    assert.equal((await service().create(token(),c)).workload.revision,1);assert.equal((await db.query("SELECT status FROM managed_product_workloads WHERE id=$1",[c.id])).rows[0]!.status,"retired");
    assert.equal((await db.query("SELECT count(*)::int n FROM managed_workload_operations")).rows[0]!.n,3);
  });
  it("denies anonymous, ordinary, expired, revoked, inactive Human and inactive administrator sessions without writes",async()=>{
    const c=input();assert.equal((await request("create",c,"")).statusCode,401);assert.equal((await request("create",c,humanBearer)).statusCode,403);
    for(const [sql,params] of [["UPDATE sessions SET status='revoked' WHERE id=$1",[bearer]],["UPDATE sessions SET status='active',expires_at=now()-interval '1 second' WHERE id=$1",[bearer]],["UPDATE sessions SET expires_at=now()+interval '1 day' WHERE id=$1",[bearer]],["UPDATE human_identities SET status='suspended' WHERE id=$1",[admin]],["UPDATE human_identities SET status='active' WHERE id=$1",[admin]],["UPDATE platform_administration_memberships SET status='suspended' WHERE human_identity_id=$1",[admin]]] as const){await db.query(sql,params);if(sql.includes("expires_at=now()+")||sql.includes("human_identities SET status='active'"))continue;assert.equal((await request("create",c)).statusCode,403);}
    assert.equal((await db.query("SELECT count(*)::int n FROM managed_product_workloads")).rows[0]!.n,0);
  });
  it("requires fresh original authentication, including renewals, and rejects future timestamps",async()=>{
    const c=input();await db.query("UPDATE sessions SET authenticated_at=now()-interval '6 minutes' WHERE id=$1",[bearer]);assert.equal((await request("create",c)).json().error.code,"FRESH_AUTHENTICATION_REQUIRED");
    await db.query("UPDATE sessions SET authenticated_at=now()+interval '1 minute' WHERE id=$1",[bearer]);assert.equal((await request("inspect",{})).statusCode,403);
    await db.query("UPDATE sessions SET authenticated_at=now()-interval '6 minutes' WHERE id=$1",[bearer]);const stored=(await db.query("SELECT authenticated_at FROM sessions WHERE id=$1",[bearer])).rows[0]!.authenticated_at;
    const renewal=await runtime.services.renewSession.execute(adminRenewalToken);assert.equal((await db.query("SELECT authenticated_at FROM sessions WHERE id=$1",[renewal.sessionId])).rows[0]!.authenticated_at.getTime(),stored.getTime());assert.equal((await request("create",c,renewal.sessionId)).statusCode,403);
  });
  it("production default gate stays closed and explicit workload gate never enables identity management",async()=>{
    const production=await buildRuntime(loadConfig({NODE_ENV:"production",REPOSITORY_MODE:"postgres",DATABASE_URL:url!,PASSWORD_HASH_MEMORY_KIB:"8192",LOG_LEVEL:"silent"}));
    try{assert.equal(production.services.administration.identityManagement!.executionEnabled,false);await assert.rejects(production.services.administration.workloads!.create(token(),input()),{code:"WORKLOAD_ADMINISTRATION_DISABLED"});}finally{await production.close();}
    const enabled=await buildRuntime(loadConfig({NODE_ENV:"production",REPOSITORY_MODE:"postgres",DATABASE_URL:url!,PASSWORD_HASH_MEMORY_KIB:"8192",LOG_LEVEL:"silent",IDENTITY_WORKLOAD_ADMINISTRATION_ENABLED:"true"}));
    try{assert.equal(enabled.services.administration.identityManagement!.executionEnabled,false);assert.equal((await enabled.services.administration.workloads!.create(token(),input())).workload.status,"active");}finally{await enabled.close();}
  });
  it("rejects spoofed mutable bindings, unsupported scopes, inactive or unknown products and protected legacy IDs",async()=>{
    const c=input();for(const change of [{productId:"unknown"},{capabilities:["team.manage"]},{capabilities:["identity.dependencies.report"]},{status:"active"},{humanIdentityId:human},{secret:"A".repeat(43)}])assert.ok((await request("create",{...c,...change})).statusCode>=400);
    await plane.saveProduct({id:"cashcast",displayName:"CashCast",status:"suspended"});assert.equal((await request("create",{...c,productId:"cashcast"})).json().error.code,"PRODUCT_NOT_AVAILABLE");
    await plane.saveWorkload({id:"legacy-workload",productId:"grocery-master",secretHash:(await ops.hash(c.secret)).value,status:"active"});
    for(const operation of ["create","rotate","revoke"]){const payload=operation==="create"?{...c,id:"legacy-workload"}:{requestId:randomUUID(),id:"legacy-workload",expectedRevision:1,reason,...(operation==="rotate"?{secret:generated()}: {})};assert.equal((await request(operation,payload)).json().error.code,"LEGACY_WORKLOAD_PROTECTED");}
    assert.equal((await request("create",{...c,id:"coco-backend"})).json().error.code,"LEGACY_WORKLOAD_PROTECTED");
    await service().create(token(),c);assert.equal((await request("rotate",{requestId:randomUUID(),id:c.id,expectedRevision:1,secret:generated(),reason,productId:"cashcast"})).statusCode,400);
    await assert.rejects(db.query("UPDATE managed_product_workloads SET product_id='cashcast' WHERE id=$1",[c.id]));await assert.rejects(db.query("UPDATE managed_product_workloads SET capabilities=ARRAY['team.manage'] WHERE id=$1",[c.id]));
  });
  it("enforces least privilege across every workload HTTP handler and trusted web mapping",async()=>{
    for(const scope of MANAGED_WORKLOAD_CAPABILITIES){
      const c=input(`scope-${scope.replaceAll('.','-')}`,[scope]);await service().create(token(),c);
      assert.equal((await context(c.id,c.secret)).statusCode,scope==="workload.context.read"?200:401);
      assert.equal((await reporting(c.id,c.secret)).statusCode,scope==="human.participation.register"?200:401);
      const headers={authorization:`Bearer ${bearer}`,"x-gama-workload-id":c.id,"x-gama-workload-secret":c.secret,"x-gama-tenant-id":"synthetic-tenant"};
      const preview=await app.inject({method:"POST",url:"/administration/platform/products/participation/backfill/preview",payload:{entries:[{humanIdentityId:human,evidenceReference:"synthetic-canonical-record"}]},headers});assert.equal(preview.statusCode,scope==="human.participation.backfill.preview"?200:401);
      for(const [method,path] of [["GET","/administration/team"],["POST","/administration/team"],["PATCH",`/administration/team/${human}/role`],["PUT",`/administration/team/${human}/product-access`],["DELETE",`/administration/team/${human}/product-access`],["DELETE",`/administration/team/${human}`]] as const){assert.equal((await app.inject({method,url:path,headers,...(["GET","DELETE"].includes(method)?{}:{payload:{}})})).statusCode,401);}
      const dependencyPayload={humanIdentityId:human,counts:{localAccounts:0,subscriptions:0,permissions:0,ownership:0,backgroundJobs:0,pendingOperations:0,externalReferences:0,retention:0},evidenceReference:"synthetic-only",observedAt:new Date().toISOString()};
      assert.equal((await app.inject({method:"POST",url:"/control/identity-dependencies",headers,payload:dependencyPayload})).statusCode,401);
      assert.equal((await app.inject({method:"POST",url:"/administration/platform/identity-management/dependencies/inspector",headers,payload:{productId:"grocery-master",workloadId:c.id}})).statusCode,409);
      assert.equal(await runtime.controlPlane.authenticateWorkload(c.id,c.secret),null);assert.equal(await runtime.controlPlane.authenticateWorkload(c.id,c.secret,"identity.dependencies.report"),null);
      assert.equal(await runtime.controlPlane.resolveWorkloadForCapability(c.id,"human.participation.register")!==null,scope==="human.participation.register");
    }
  });
  it("records exactly one canonical participation across concurrent requests and repeated sessions without memberships or entitlements",async()=>{
    const c=input();await service().create(token(),c);const before=await protectedFingerprint();
    const responses=await Promise.all(Array.from({length:8},()=>reporting(c.id,c.secret)));assert.ok(responses.every(r=>r.statusCode===200));assert.equal(responses.filter(r=>r.json().created).length,1);
    const row=(await db.query("SELECT workload_id,managed_workload_id,product_id,human_identity_id FROM human_product_participations")).rows[0]!;assert.equal(row.workload_id,null);assert.equal(row.managed_workload_id,c.id);assert.equal(row.human_identity_id,human);
    assert.deepEqual(await protectedFingerprint(),before);assert.equal((await runtime.services.administration.controlCentre!.productDirectory(token())).products.find(p=>p.id==="grocery-master")!.workloads,1);
    const fresh=await runtime.services.login.execute({email:"human@workload.synthetic.example",password});assert.equal((await reporting(c.id,c.secret,fresh.sessionId)).json().created,false);
    assert.equal((await db.query("SELECT count(*)::int n FROM platform_audit_events WHERE event_type='human.product.participation.registered'")).rows[0]!.n,1);
  });
  it("requires admin bearer for backfill previews and never writes preview relationships",async()=>{
    const c=input();await service().create(token(),c);const headers={"x-gama-workload-id":c.id,"x-gama-workload-secret":c.secret};
    const r=await app.inject({method:"POST",url:"/administration/platform/products/participation/backfill/preview",headers:{...headers,authorization:`Bearer ${humanBearer}`},payload:{entries:[]}});assert.equal(r.statusCode,403);
    const preview=await runtime.services.administration.controlCentre!.previewParticipationBackfill(token(),c.id,c.secret,[{humanIdentityId:human,evidenceReference:"actual-synthetic-record"}]);assert.equal(preview.productionExecutionAvailable,false);assert.equal(preview.rows[0]!.status,"eligible_canonical_workload_assertion");assert.equal((await db.query("SELECT count(*)::int n FROM human_product_participations")).rows[0]!.n,0);
  });
  it("serializes concurrent creates and exact request replay across separate connections",async()=>{
    const c=input();const remote=new WorkloadAdministration(second,new PostgresControlPlaneRepository(second),ops,{now:()=>new Date()},true);
    const results=await Promise.all([service().create(token(),c),remote.create(token(),c)]);assert.equal(results.filter(r=>r.replayed).length,1);assert.equal((await db.query("SELECT count(*)::int n FROM managed_product_workloads")).rows[0]!.n,1);
    const fresh=input("new-conflict");const results2=await Promise.allSettled([service().create(token(),fresh),remote.create(token(),{...fresh,requestId:randomUUID(),secret:generated()})]);assert.equal(results2.filter(r=>r.status==="fulfilled").length,1);
  });
  it("compare-and-swap makes exactly one concurrent rotation succeed without overlap",async()=>{
    const c=input();await service().create(token(),c);const remote=new WorkloadAdministration(second,new PostgresControlPlaneRepository(second),ops,{now:()=>new Date()},true);
    const r1={requestId:randomUUID(),id:c.id,expectedRevision:1,secret:generated(),reason},r2={...r1,requestId:randomUUID(),secret:generated()};
    const results=await Promise.allSettled([service().rotate(token(),r1),remote.rotate(token(),r2)]);assert.equal(results.filter(r=>r.status==="fulfilled").length,1);const loser=results.find(r=>r.status==="rejected") as PromiseRejectedResult;assert.equal(loser.reason.code,"WORKLOAD_REVISION_CONFLICT");
    assert.equal(await runtime.controlPlane.authenticateWorkload(c.id,c.secret,"workload.context.read"),null);assert.equal(Number(await runtime.controlPlane.authenticateWorkload(c.id,r1.secret,"workload.context.read")!==null)+Number(await runtime.controlPlane.authenticateWorkload(c.id,r2.secret,"workload.context.read")!==null),1);
  });
  it("holds credential authorization through reporting commit while revoke waits, then denies later reports",async()=>{
    const c=input();await service().create(token(),c);let release!:()=>void;const held=new Promise<void>(r=>release=r);let reached!:()=>void;const locked=new Promise<void>(r=>reached=r);
    const registration=db.withTransaction(async()=>{const authority=await plane.findManagedWorkload(c.id);assert.equal(authority?.status,"active");reached();await held;return new PostgresControlCentreRepository(db).registerParticipation(human,"grocery-master",c.id,new Date());});await locked;
    const remote=new WorkloadAdministration(second,new PostgresControlPlaneRepository(second),ops,{now:()=>new Date()},true);let completed=false;const revocation=remote.revoke(token(),{requestId:randomUUID(),id:c.id,expectedRevision:1,reason}).then(r=>{completed=true;return r;});await new Promise(r=>setTimeout(r,50));assert.equal(completed,false);release();assert.equal(await registration,true);await revocation;assert.equal((await reporting(c.id,c.secret)).statusCode,401);
  });
  it("holds credential authorization through reporting commit while rotation waits, then only accepts new secret",async()=>{
    const c=input();await service().create(token(),c);let release!:()=>void;const held=new Promise<void>(r=>release=r);let reached!:()=>void;const locked=new Promise<void>(r=>reached=r);
    const registration=db.withTransaction(async()=>{await plane.findManagedWorkload(c.id);reached();await held;return new PostgresControlCentreRepository(db).registerParticipation(human,"grocery-master",c.id,new Date());});await locked;
    const remote=new WorkloadAdministration(second,new PostgresControlPlaneRepository(second),ops,{now:()=>new Date()},true);const next=generated();let completed=false;const rotation=remote.rotate(token(),{requestId:randomUUID(),id:c.id,expectedRevision:1,secret:next,reason}).then(r=>{completed=true;return r;});await new Promise(r=>setTimeout(r,50));assert.equal(completed,false);release();assert.equal(await registration,true);await rotation;assert.equal((await reporting(c.id,c.secret)).statusCode,401);assert.equal((await reporting(c.id,next)).statusCode,200);
  });
  it("rechecks inactive managed workload, scope and product at registration commit",async()=>{
    const c=input();await service().create(token(),c);await service().revoke(token(),{requestId:randomUUID(),id:c.id,expectedRevision:1,reason});await assert.rejects(db.withTransaction(()=>new PostgresControlCentreRepository(db).registerParticipation(human,"grocery-master",c.id,new Date())),{code:"PARTICIPATION_AUTHORITY_INVALID"});
    const d=input("context-only",["workload.context.read"]);await service().create(token(),d);await assert.rejects(db.withTransaction(()=>new PostgresControlCentreRepository(db).registerParticipation(human,"grocery-master",d.id,new Date())),{code:"PARTICIPATION_AUTHORITY_INVALID"});
    await plane.saveProduct({id:"grocery-master",displayName:"Grocery",status:"suspended"});assert.equal((await context(d.id,d.secret)).statusCode,401);
  });
  it("rolls back credential creation, rotation, revocation and idempotency receipt if audit fails",async()=>{
    const original=plane.appendAudit.bind(plane),failing=new WorkloadAdministration(db,plane,ops,{now:()=>new Date()},true),c=input();plane.appendAudit=async()=>{throw new Error("Synthetic audit unavailable");};
    try{await assert.rejects(failing.create(token(),c));assert.equal((await db.query("SELECT count(*)::int n FROM managed_product_workloads")).rows[0]!.n,0);assert.equal((await db.query("SELECT count(*)::int n FROM managed_workload_operations")).rows[0]!.n,0);}finally{plane.appendAudit=original;}
    await failing.create(token(),c);const before=(await db.query("SELECT md5(to_jsonb(w)::text) fingerprint FROM managed_product_workloads w WHERE id=$1",[c.id])).rows[0]!.fingerprint;
    plane.appendAudit=async()=>{throw new Error("Synthetic audit unavailable");};try{await assert.rejects(failing.rotate(token(),{requestId:randomUUID(),id:c.id,expectedRevision:1,secret:generated(),reason}));await assert.rejects(failing.revoke(token(),{requestId:randomUUID(),id:c.id,expectedRevision:1,reason}));assert.equal((await db.query("SELECT md5(to_jsonb(w)::text) fingerprint FROM managed_product_workloads w WHERE id=$1",[c.id])).rows[0]!.fingerprint,before);assert.equal((await db.query("SELECT count(*)::int n FROM managed_workload_operations")).rows[0]!.n,1);}finally{plane.appendAudit=original;}
  });
  it("pins authority locks against concurrent admin membership revocation during atomic audit",async()=>{
    let release!:()=>void;const held=new Promise<void>(r=>release=r);let reached!:()=>void;const entered=new Promise<void>(r=>reached=r);const original=plane.appendAudit.bind(plane);
    plane.appendAudit=async event=>{reached();await held;return original(event);};const guarded=new WorkloadAdministration(db,plane,ops,{now:()=>new Date()},true);const create=guarded.create(token(),input());await entered;
    let changed=false;const revoke=second.query("UPDATE platform_administration_memberships SET status='retired' WHERE human_identity_id=$1",[admin]).then(()=>{changed=true;});await new Promise(r=>setTimeout(r,50));assert.equal(changed,false);release();try{await create;await revoke;await assert.rejects(guarded.inspect(token(),{}),{code:"NOT_PLATFORM_ADMIN"});}finally{plane.appendAudit=original;}
  });
  it("namespace trigger rejects concurrent cross-store collisions and preserves legacy rows",async()=>{
    const c=input("namespace-race"),hash=(await ops.hash(c.secret)).value;let release!:()=>void;const held=new Promise<void>(r=>release=r);let reached!:()=>void;const entered=new Promise<void>(r=>reached=r);
    const legacy=db.withTransaction(async()=>{await plane.saveWorkload({id:c.id,productId:"grocery-master",secretHash:hash,status:"active"});reached();await held;});await entered;
    const managed=second.query("INSERT INTO managed_product_workloads(id,product_id,secret_hash,status,revision,capabilities,created_at,updated_at) VALUES($1,'grocery-master',$2,'active',1,ARRAY['human.participation.register'],now(),now())",[c.id,hash]);release();await legacy;await assert.rejects(managed);
    const d=input("managed-first");await service().create(token(),d);await assert.rejects(plane.saveWorkload({id:d.id,productId:"grocery-master",secretHash:hash,status:"active"}));assert.equal((await plane.findWorkload(c.id))!.secretHash,hash);assert.equal(await plane.findWorkload(d.id),null);
  });
  it("managed participation has exactly one authority and cannot bind to a different product",async()=>{
    const c=input();await service().create(token(),c);
    await assert.rejects(db.query("INSERT INTO human_product_participations(human_identity_id,product_id,status,created_at,updated_at) VALUES($1,'grocery-master','active',now(),now())",[human]));
    await assert.rejects(db.query("INSERT INTO human_product_participations(human_identity_id,product_id,managed_workload_id,status,created_at,updated_at) VALUES($1,'cashcast',$2,'active',now(),now())",[human,c.id]));
    assert.equal((await reporting(c.id,c.secret)).statusCode,200);
  });
  it("trusted registered web reporting enforces managed register scope and exact active product binding",async()=>{
    const c=input("web-context-only",["workload.context.read"]);await service().create(token(),c);
    const configured=async(workload:string)=>buildRuntime(loadConfig({NODE_ENV:"test",REPOSITORY_MODE:"postgres",DATABASE_URL:url!,PASSWORD_HASH_MEMORY_KIB:"8192",LOG_LEVEL:"silent",IDENTITY_PRODUCT_INTEGRATIONS:JSON.stringify([{productId:"grocery-master",integrationStatus:"gama_identity",participationRecording:"verified",evidenceReference:"synthetic-source-fixture",verifiedAt:"2026-10-11T00:00:00Z",webAppIds:["synthetic-grocery-web"],reportingWorkloadId:workload}])}));
    const denied=await configured(c.id);try{await assert.rejects(denied.services.administration.controlCentre!.participateFromWebAuthentication(SessionId.from(humanBearer),"synthetic-grocery-web"),{code:"PARTICIPATION_REPORTING_UNAVAILABLE"});assert.equal((await db.query("SELECT count(*)::int n FROM human_product_participations")).rows[0]!.n,0);}finally{await denied.close();}
    const d=input("web-register-only",["human.participation.register"]);await service().create(token(),d);const allowed=await configured(d.id);try{const first=await allowed.services.administration.controlCentre!.participateFromWebAuthentication(SessionId.from(humanBearer),"synthetic-grocery-web");assert.equal(first!.created,true);assert.equal((await allowed.services.administration.controlCentre!.participateFromWebAuthentication(SessionId.from(humanBearer),"synthetic-grocery-web"))!.created,false);assert.equal(await allowed.services.administration.controlCentre!.participateFromWebAuthentication(SessionId.from(humanBearer),"unregistered-app"),null);}finally{await allowed.close();}
  });
  it("isolated backfill simulation requires both preview and registration scopes and production execution stays unavailable",async()=>{
    const c=input("preview-only",["human.participation.backfill.preview"]);await service().create(token(),c);const entries=[{humanIdentityId:human,evidenceReference:"synthetic-existing-canonical-record"}];
    await assert.rejects(runtime.services.administration.controlCentre!.simulateParticipationBackfill(token(),c.id,c.secret,entries),{code:"PARTICIPATION_AUTHORITY_INVALID"});assert.equal((await db.query("SELECT count(*)::int n FROM human_product_participations")).rows[0]!.n,0);
    const d=input("preview-register",["human.participation.backfill.preview","human.participation.register"]);await service().create(token(),d);const result=await runtime.services.administration.controlCentre!.simulateParticipationBackfill(token(),d.id,d.secret,entries);assert.equal(result.results[0]!.created,true);
  });
  it("keeps failed, malformed and oversized operator requests non-cacheable with safe error bodies",async()=>{
    for(const requestOptions of [
      {headers:{"content-type":"application/json",authorization:`Bearer ${bearer}`},payload:"{invalid"},
      {headers:{"content-type":"application/json",authorization:`Bearer ${bearer}`},payload:JSON.stringify({unexpected:"x".repeat(9000)})},
      {headers:{},payload:{}},
      {headers:{authorization:`Bearer ${humanBearer}`},payload:input()},
    ]){const response=await app.inject({method:"POST",url:"/administration/platform/workloads/create",...requestOptions});assert.ok(response.statusCode>=400);assert.equal(response.headers["cache-control"],"no-store");assert.equal(response.headers.pragma,"no-cache");assert.ok(!response.body.includes("password_hash"));assert.ok(!response.body.includes("$argon2"));}
  });
  it("rejects known bearer and workload credentials in audit reasons without writes or disclosure",async()=>{
    const c=input();for(const privateValue of [bearer,c.secret]){const response=await request("create",{...c,reason:`Review ${privateValue}`});assert.equal(response.statusCode,400);assert.equal(response.json().error.code,"INVALID_REQUEST");assert.ok(!response.body.includes(privateValue));}
    assert.equal((await db.query("SELECT count(*)::int n FROM managed_product_workloads")).rows[0]!.n,0);assert.equal((await db.query("SELECT count(*)::int n FROM managed_workload_operations")).rows[0]!.n,0);assert.equal((await db.query("SELECT count(*)::int n FROM platform_audit_events WHERE event_type LIKE 'workload.managed.%'")).rows[0]!.n,0);
    await service().create(token(),c);const rotate={requestId:randomUUID(),id:c.id,expectedRevision:1,secret:generated(),reason};await assert.rejects(service().rotate(token(),{...rotate,reason:`Review ${rotate.secret}`}),{code:"INVALID_REQUEST"});await assert.rejects(service().revoke(token(),{requestId:randomUUID(),id:c.id,expectedRevision:1,reason:`Review ${bearer}`}),{code:"INVALID_REQUEST"});assert.equal((await db.query("SELECT revision FROM managed_product_workloads WHERE id=$1",[c.id])).rows[0]!.revision,1);
  });
  it("executes the actual guarded operator transport against the isolated HTTP administration service",async()=>{
    const c=input(),operator=buildApp(runtime.services,runtime.databaseHealth);await operator.listen({host:"127.0.0.1",port:0});
    try{const address=operator.server.address();assert.ok(address&&typeof address!=="string");const result=await executeOperatorRequest({operation:"create",execute:true,allowSyntheticLoopback:true,baseURL:`http://127.0.0.1:${address.port}`,id:c.id,productId:c.productId,requestId:c.requestId,reason:c.reason,capabilities:c.capabilities,secretFile:"synthetic-protected-file",bearerFD:0},bearer,c.secret);assert.equal(result.replayed,false);assert.equal((result.workload as {id:string}).id,c.id);assert.ok(!JSON.stringify(result).includes(c.secret));assert.ok(!JSON.stringify(result).includes(bearer));}finally{await operator.close();}
  });
  it("rejects bearer values accidentally copied into request IDs or workload metadata before audit persistence",async()=>{
    const c=input();for(const change of [{requestId:bearer},{requestId:bearer.toUpperCase()},{id:`leak-${bearer}`},{productId:`leak-${bearer}`}]){const response=await request("create",{...c,...change});assert.equal(response.statusCode,400);assert.ok(!response.body.includes(bearer));}
    const inspect=await request("inspect",{id:`leak-${bearer}`});assert.equal(inspect.statusCode,400);assert.ok(!inspect.body.includes(bearer));assert.equal((await db.query("SELECT count(*)::int n FROM managed_product_workloads")).rows[0]!.n,0);assert.equal((await db.query("SELECT count(*)::int n FROM platform_audit_events WHERE event_type LIKE 'workload.managed.%'")).rows[0]!.n,0);
  });
  it("reports active workload totals separately from actual participation-register authority without guessing integration",async()=>{
    const c=input("only-context",["workload.context.read"]),p=input("only-preview",["human.participation.backfill.preview"]);await service().create(token(),c);await service().create(token(),p);
    const product=async()=>(await runtime.services.administration.controlCentre!.productDirectory(token())).products.find(row=>row.id==="grocery-master")!;
    const absent=await product();assert.equal(absent.workloads,2);assert.equal(absent.reportingWorkloads,0);assert.equal(absent.participationCoverage,"no_authenticated_reporting_workload");assert.equal(absent.integrationStatus,"unknown");
    const r=input("only-register",["human.participation.register"]);await service().create(token(),r);const present=await product();assert.equal(present.workloads,3);assert.equal(present.reportingWorkloads,1);assert.equal(present.participationCoverage,"reporting_contract_available");assert.equal(present.integrationStatus,"unknown");
    await service().revoke(token(),{requestId:randomUUID(),id:r.id,expectedRevision:1,reason});assert.equal((await product()).reportingWorkloads,0);assert.equal((await product()).workloads,2);
  });
  it("supports metadata-only bounded pagination without secret/hash projections",async()=>{
    for(let i=0;i<51;i++)await service().create(token(),input(`page-${String(i).padStart(2,'0')}`,["human.participation.register"]));
    const first=await service().inspect(token(),{});assert.equal(first.workloads.length,50);assert.ok(first.nextCursor);const secondPage=await service().inspect(token(),{cursor:first.nextCursor});assert.equal(secondPage.workloads.length,1);assert.equal(secondPage.nextCursor,null);assert.ok(!JSON.stringify(first).includes("secret"));
  });
});
