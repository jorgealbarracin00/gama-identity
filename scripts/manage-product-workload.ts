/** Development candidate only. No environment credentials, SQL or provider/account APIs. */
import { pathToFileURL } from "node:url";
import { createPrivateSecretFile, dryRunSummary, executeOperatorRequest, OperatorGuardError, parseOperatorArguments, readPrivateBearerFD, readPrivateCredential } from "./manage-product-workload-helpers.js";

const usage = `GAMA managed reporting workload operator — default dry run
Run with Node 22 and tsx. No secrets or bearer values are accepted in arguments or environment.
generate-secret --secret-file NEW_PATH [--execute-reviewed]
inspect --base-url APPROVED_ORIGIN [--id ID | --cursor ID]
create --base-url APPROVED_ORIGIN --request-id UUID --id ID --product-id ID --capabilities scope,scope --reason TEXT --secret-file PRIVATE_PATH
rotate --base-url APPROVED_ORIGIN --request-id UUID --id ID --expected-revision N --reason TEXT --secret-file PRIVATE_PATH
revoke --base-url APPROVED_ORIGIN --request-id UUID --id ID --expected-revision N --reason TEXT
Server execution additionally requires --execute-reviewed and exactly one --bearer-file PRIVATE_0600_PATH or --bearer-fd N.
Only the existing approved HTTPS Identity origin is accepted. Synthetic http://127.0.0.1:PORT additionally requires --allow-synthetic-loopback.
The CLI does not obtain sessions or bypass the server’s fresh-administrator check. Review exact intent before execution.
Keep a create/rotate request UUID and its secret file for idempotent retries; inspect before any new command. No automatic retry occurs.`;

export async function runOperatorCLI(args: readonly string[]): Promise<void> {
  if(args.length===1 && args[0]==="--help") { process.stdout.write(usage+"\n"); return; }
  const options=parseOperatorArguments(args);
  if(!options.execute) { process.stdout.write(JSON.stringify(dryRunSummary(options),null,2)+"\n"); return; }
  if(options.operation==="generate-secret") { await createPrivateSecretFile(options.secretFile!); process.stdout.write(JSON.stringify({operation:options.operation,secretFile:options.secretFile,mode:"0600",created:true,requestSent:false})+"\n"); return; }
  const bearer=options.bearerFile!==undefined ? await readPrivateCredential(options.bearerFile,"bearer") : await readPrivateBearerFD(options.bearerFD!);
  const secret=options.operation==="create"||options.operation==="rotate" ? await readPrivateCredential(options.secretFile!,"secret") : undefined;
  const result=await executeOperatorRequest(options,bearer,secret);
  process.stdout.write(JSON.stringify(result,null,2)+"\n");
}

if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  runOperatorCLI(process.argv.slice(2)).catch(error=>{
    // Never forward network/filesystem error text, response bodies, arguments or credentials.
    process.stderr.write((error instanceof OperatorGuardError ? error.message : "The workload operator failed safely")+"\n");
    process.exitCode=1;
  });
}
