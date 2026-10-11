import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, link, mkdtemp, open, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { APPROVED_IDENTITY_ORIGIN, approvedEndpoint, commandPayload, createPrivateSecretFile, dryRunSummary, executeOperatorRequest, metadataOnlyResult, normalizeCredentialInput, OperatorGuardError, parseOperatorArguments, readPrivateBearerFD, readPrivateCredential, validGeneratedSecret, type OperatorOptions } from "../../scripts/manage-product-workload-helpers.js";

const requestID="a6d7ac80-a70b-4c2d-8a76-e4eb12eb5930";
const bearer="synthetic-administrator-session-0001";
const generatedSecret=()=>randomBytes(32).toString("base64url");
const createArgs=["create","--base-url",APPROVED_IDENTITY_ORIGIN,"--request-id",requestID,"--id","cashcast-preview-reporter","--product-id","cashcast","--capabilities","human.participation.register","--reason","Reviewed synthetic registration","--secret-file","/nonexistent/secret-0600"];
const executing=():OperatorOptions=>parseOperatorArguments([...createArgs,"--execute-reviewed","--bearer-file","/nonexistent/admin-0600"]);
const metadata={id:"cashcast-preview-reporter",productId:"cashcast",status:"active",revision:1,capabilities:["human.participation.register"],createdAt:"2026-10-12T00:00:00Z",updatedAt:"2026-10-12T00:00:00Z"};
const temporary=async()=>mkdtemp(join(tmpdir(),"gama-workload-cli-test-"));

test("workload operator requires exact approved HTTPS origin or explicit canonical synthetic loopback",()=>{
  assert.equal(approvedEndpoint(APPROVED_IDENTITY_ORIGIN,"create"),APPROVED_IDENTITY_ORIGIN+"/administration/platform/workloads/create");
  assert.equal(approvedEndpoint(APPROVED_IDENTITY_ORIGIN+":443/","inspect"),APPROVED_IDENTITY_ORIGIN+"/administration/platform/workloads/inspect");
  for(const url of ["http://gama-identity-production.up.railway.app","https://gama-identity-production.up.railway.app.evil.example","https://user:password@gama-identity-production.up.railway.app","https://gama-identity-production.up.railway.app:444","https://gama-identity-production.up.railway.app/path","https://gama-identity-production.up.railway.app?token=x","https://gama-identity-production.up.railway.app#fragment","https://evil.example","http://127.0.0.1:3131"])assert.throws(()=>approvedEndpoint(url,"create"),OperatorGuardError);
  assert.equal(approvedEndpoint("http://127.0.0.1:3131","inspect",true),"http://127.0.0.1:3131/administration/platform/workloads/inspect");
  for(const url of ["http://localhost:3131","http://127.1:3131","http://2130706433:3131","http://127.0.0.1:03131","http://127.0.0.1:0","http://127.0.0.1:65536","http://127.0.0.1:3131/path"])assert.throws(()=>approvedEndpoint(url,"inspect",true),OperatorGuardError);
});
test("workload operator defaults to dry run and forbids credential arguments or unrelated command options",()=>{
  const options=parseOperatorArguments(createArgs),summary=dryRunSummary(options);
  assert.equal(options.execute,false);assert.equal(summary.credentialsRead,false);assert.equal(summary.requestSent,false);
  assert.equal("secret" in summary,false);assert.equal("reason" in summary,false);assert.equal("bearerFile" in summary,false);
  for(const args of [[...createArgs,"--secret",generatedSecret()],[...createArgs,"--bearer",bearer],[...createArgs,"--id","different-id"],[...createArgs,"--expected-revision","1"],[...createArgs,"--execute-reviewed"],[...createArgs,"--execute-reviewed","--bearer-file","file","--bearer-fd","0"],[...createArgs,"--capabilities","team.manage"],[...createArgs,"--bearer-fd","-1"]])assert.throws(()=>parseOperatorArguments(args),OperatorGuardError);
});
test("workload operator validates reviewed revisions, unique scopes and bounded ordinary reasons",()=>{
  const rotate=["rotate","--base-url",APPROVED_IDENTITY_ORIGIN,"--request-id",requestID,"--id","cashcast-preview-reporter","--expected-revision","2","--reason","Reviewed synthetic rotation","--secret-file","file"];
  assert.equal(parseOperatorArguments(rotate).expectedRevision,2);
  const scopeIndex=createArgs.indexOf("human.participation.register"),reasonIndex=createArgs.indexOf("Reviewed synthetic registration");
  for(const bad of ["human.participation.register,human.participation.register","identity.dependencies.report",""]) {const args=[...createArgs];args[scopeIndex]=bad;assert.throws(()=>parseOperatorArguments(args),OperatorGuardError);}
  for(const bad of ["short","review\nline", "x".repeat(241)," leading reason "]) {const args=[...createArgs];args[reasonIndex]=bad;assert.throws(()=>parseOperatorArguments(args),OperatorGuardError);}
  for(const bad of ["0","01","2147483647","NaN"]) {const args=[...rotate];args[args.indexOf("2")]=bad;assert.throws(()=>parseOperatorArguments(args),OperatorGuardError);}
});
test("workload operator uses canonical generated 32-byte secrets and rejects weak or malformed credentials",()=>{
  const secret=generatedSecret();assert.equal(validGeneratedSecret(secret),true);assert.equal(normalizeCredentialInput(secret+"\n","secret").length,43);
  for(const value of ["a".repeat(43),secret+" ",secret+"\n\n",secret.slice(1),"human-password"])assert.equal(validGeneratedSecret(value),false);
  for(const value of ["short",bearer+"\nextra",bearer+"\r\n\r\n"," "+bearer,"x".repeat(201)])assert.throws(()=>normalizeCredentialInput(value,"bearer"),OperatorGuardError);
  assert.equal(normalizeCredentialInput(bearer+"\r\n","bearer"),bearer);
});
test("workload operator generates private files without overwrite or symlink following",async()=>{
  const directory=await temporary();try {
    const path=join(directory,"secret");await createPrivateSecretFile(path);
    assert.equal((await stat(path)).mode&0o777,0o600);assert.equal(validGeneratedSecret(await readPrivateCredential(path,"secret")),true);
    const before=await readFile(path);await assert.rejects(()=>createPrivateSecretFile(path),OperatorGuardError);assert.equal((await readFile(path)).equals(before),true);
    const alias=join(directory,"alias");await symlink(path,alias);await assert.rejects(()=>createPrivateSecretFile(alias),OperatorGuardError);await assert.rejects(()=>readPrivateCredential(alias,"secret"),OperatorGuardError);
  }finally{await rm(directory,{recursive:true,force:true});}
});
test("workload operator private input rejects public modes, hard links, oversized files and directories",async()=>{
  const directory=await temporary();try {
    const path=join(directory,"bearer");await writeFile(path,bearer,{mode:0o600});assert.equal((await readPrivateCredential(path,"bearer")).length,bearer.length);
    await chmod(path,0o644);await assert.rejects(()=>readPrivateCredential(path,"bearer"),OperatorGuardError);await chmod(path,0o600);
    const alias=join(directory,"hardlink");await link(path,alias);await assert.rejects(()=>readPrivateCredential(path,"bearer"),OperatorGuardError);await rm(alias);
    await writeFile(path,"x".repeat(4097));await assert.rejects(()=>readPrivateCredential(path,"bearer"),OperatorGuardError);await assert.rejects(()=>readPrivateCredential(directory,"bearer"),OperatorGuardError);
  }finally{await rm(directory,{recursive:true,force:true});}
});
test("workload operator supports owned private input descriptors without closing or exposing them",async()=>{
  const directory=await temporary();try {
    const path=join(directory,"bearer");await writeFile(path,bearer,{mode:0o600});const file=await open(path,"r");
    try {assert.equal((await readPrivateBearerFD(file.fd)).length,bearer.length);assert.equal((await file.stat()).isFile(),true);}finally{await file.close();}
    await chmod(path,0o644);const publicFile=await open(path,"r");try{await assert.rejects(()=>readPrivateBearerFD(publicFile.fd),OperatorGuardError);}finally{await publicFile.close();}
    await assert.rejects(()=>readPrivateBearerFD(-1),OperatorGuardError);
  }finally{await rm(directory,{recursive:true,force:true});}
});
test("workload operator request payload preserves exact request IDs and uses metadata-only operation shapes",()=>{
  const options=executing(),secret=generatedSecret(),payload=commandPayload(options,secret);
  assert.equal(payload.requestId,requestID);assert.equal(payload.id,options.id);assert.equal(payload.productId,"cashcast");assert.equal(typeof payload.secret,"string");
  const revoke=parseOperatorArguments(["revoke","--base-url",APPROVED_IDENTITY_ORIGIN,"--id","cashcast-preview-reporter","--request-id",requestID,"--expected-revision","2","--reason","Reviewed synthetic revocation"]);
  assert.equal("secret" in commandPayload(revoke),false);assert.equal(commandPayload(revoke).expectedRevision,2);
  assert.deepEqual(commandPayload(parseOperatorArguments(["inspect","--base-url",APPROVED_IDENTITY_ORIGIN,"--id","cashcast-preview-reporter"])),{id:"cashcast-preview-reporter"});
});
test("workload operator transport is one-shot, no-store, bounded and rejects redirects or raw server errors",async()=>{
  const options=executing(),secret=generatedSecret();let calls=0;
  const transport:typeof fetch=async(input,init)=>{
    calls++;assert.equal(String(input),APPROVED_IDENTITY_ORIGIN+"/administration/platform/workloads/create");assert.equal(init?.redirect,"error");assert.equal(init?.cache,"no-store");assert.equal(init?.method,"POST");assert.equal(typeof (init?.headers as Record<string,string>).Authorization,"string");assert.ok(init?.signal);
    return Response.json({workload:metadata,replayed:false,secret,token:bearer,secretHash:"server-extra-hash"});
  };
  const result=await executeOperatorRequest(options,bearer,secret,transport);assert.equal(calls,1);assert.equal(JSON.stringify(result).includes(secret),false);assert.equal(JSON.stringify(result).includes(bearer),false);assert.equal(JSON.stringify(result).includes("server-extra-hash"),false);
  for(const response of [new Response("raw error "+bearer+secret,{status:500}),new Response(null,{status:302,headers:{Location:"https://evil.example"}}),new Response("x".repeat(32769),{status:200}),Response.json({workload:{...metadata,id:"wrong-workload"},replayed:false})]){
    let count=0;await assert.rejects(()=>executeOperatorRequest(options,bearer,secret,async()=>{count++;return response;}),(error:unknown)=>error instanceof OperatorGuardError&&!error.message.includes(secret)&&!error.message.includes(bearer));assert.equal(count,1);
  }
});
test("workload operator metadata projection binds the workload and forbids credential echo or review metadata leakage",async()=>{
  const options=executing(),secret=generatedSecret();
  assert.deepEqual(metadataOnlyResult({workload:metadata,replayed:true,secretHash:"not-output"},options),{workload:metadata,replayed:true});
  assert.throws(()=>metadataOnlyResult({workload:{...metadata,productId:"other-product"},replayed:false},options),OperatorGuardError);
  let called=false;await assert.rejects(()=>executeOperatorRequest({...options,reason:bearer},bearer,secret,async()=>{called=true;return Response.json({});}),OperatorGuardError);assert.equal(called,false);
  const inspect=parseOperatorArguments(["inspect","--base-url",APPROVED_IDENTITY_ORIGIN,"--execute-reviewed","--bearer-file","file"]);
  await assert.rejects(()=>executeOperatorRequest(inspect,bearer,undefined,async()=>Response.json({workloads:[{...metadata,id:bearer}],nextCursor:null})),OperatorGuardError);
});
test("workload operator rejects known credentials in every request metadata field before transport, including normalized UUIDs",async()=>{
  const options=executing(),secret=generatedSecret();
  const inspect:OperatorOptions={operation:"inspect",execute:true,allowSyntheticLoopback:false,baseURL:APPROVED_IDENTITY_ORIGIN,bearerFile:"/nonexistent/admin-0600"};
  const rejected:[OperatorOptions,string,string|undefined][]=[
    [{...options,requestId:requestID.toUpperCase()},requestID,secret],
    [{...options,id:requestID},requestID,secret],
    [{...options,productId:requestID},requestID,secret],
    [{...options,reason:"Reviewed "+requestID.toUpperCase()},requestID,secret],
    [{...options,reason:"Reviewed "+secret},bearer,secret],
    [{...inspect,id:requestID},requestID,undefined],
    [{...inspect,cursor:requestID},requestID,undefined]
  ];
  let calls=0;
  for(const [command,knownBearer,knownSecret] of rejected) {
    await assert.rejects(()=>executeOperatorRequest(command,knownBearer,knownSecret,async()=>{calls++;return Response.json({});}),
      (error:unknown)=>error instanceof OperatorGuardError&&!error.message.toLowerCase().includes(knownBearer.toLowerCase())&&(!knownSecret||!error.message.includes(knownSecret)));
  }
  assert.equal(calls,0);
});
test("workload operator actual CLI dry run reads no credential files and emits no environment credentials",()=>{
  const child=execFileSync(process.execPath,["--import","tsx",resolve("scripts/manage-product-workload.ts"),...createArgs],{encoding:"utf8",env:{...process.env,GAMA_ADMIN_BEARER:bearer,GAMA_WORKLOAD_SECRET:"synthetic-env-secret-never-used"}});
  const result=JSON.parse(child);assert.equal(result.dryRun,true);assert.equal(result.credentialsRead,false);assert.equal(result.requestSent,false);assert.equal(child.includes(bearer),false);assert.equal(child.includes("synthetic-env-secret-never-used"),false);
});
test("workload operator actual CLI rejects raw credential arguments with sanitized output",()=>{
  const syntheticSecret=generatedSecret();
  try {
    execFileSync(process.execPath,["--import","tsx",resolve("scripts/manage-product-workload.ts"),...createArgs,"--secret",syntheticSecret],{encoding:"utf8",stdio:"pipe"});
    assert.fail("A raw credential argument was accepted");
  } catch(error) {
    const rejected=error as {status:number;stdout:string;stderr:string};assert.equal(rejected.status,1);
    assert.equal(String(rejected.stdout).includes(syntheticSecret),false);assert.equal(String(rejected.stderr).includes(syntheticSecret),false);
  }
});
test("workload operator actual CLI default secret generation is dry and existing reviewed files are preserved",async()=>{
  const directory=await temporary();try {
    const path=join(directory,"secret"),script=resolve("scripts/manage-product-workload.ts");
    const dry=JSON.parse(execFileSync(process.execPath,["--import","tsx",script,"generate-secret","--secret-file",path],{encoding:"utf8"}));assert.equal(dry.dryRun,true);await assert.rejects(()=>stat(path));
    const result=JSON.parse(execFileSync(process.execPath,["--import","tsx",script,"generate-secret","--secret-file",path,"--execute-reviewed"],{encoding:"utf8"}));assert.equal(result.created,true);assert.equal(result.mode,"0600");assert.equal(result.requestSent,false);
    const original=await readFile(path);try{execFileSync(process.execPath,["--import","tsx",script,"generate-secret","--secret-file",path,"--execute-reviewed"],{encoding:"utf8",stdio:"pipe"});assert.fail("Existing file overwrite was accepted");}catch(error){assert.equal((error as {status:number}).status,1);assert.equal(String((error as {stderr:Buffer}).stderr).includes(original.toString().trim()),false);}assert.equal((await readFile(path)).equals(original),true);
  }finally{await rm(directory,{recursive:true,force:true});}
});
