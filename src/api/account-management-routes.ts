import { InvalidLoginError } from "../operations/application/errors.js";
import { FederatedAuthenticationError } from "../authentication/federated/application/errors.js";
import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";
import type { IdentityServices } from "./services.js";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";
import { EmailAlreadyInUseError, InvalidEmailError, InvalidPasswordError } from "../authentication/credentials/domain/errors.js";
import { EmailSecurityRateLimitError, TrustedIdentityAppError } from "../authentication/email-security/application.js";

export function accountSession(request: FastifyRequest): SessionId {
  const header = request.headers.authorization;
  if (typeof header !== "string" || !/^Bearer [^\s]{1,200}$/u.test(header)) throw new AppError("Sign in to continue", "UNAUTHORIZED", 401);
  return SessionId.from(header.slice(7));
}

export function accountManagementRoutes(services: IdentityServices): FastifyPluginAsync {
  return async app => {
    const handle = async (request: FastifyRequest, work: (m: NonNullable<IdentityServices["accountManagement"]>, session: SessionId) => Promise<unknown>) => {
      const session = accountSession(request);
      if (!services.accountManagement) throw new AppError("Account management is unavailable", "ACCOUNT_MANAGEMENT_UNAVAILABLE", 503);
      try { return await work(services.accountManagement, session); }
      catch (error) {
        if (error instanceof InvalidLoginError || error instanceof FederatedAuthenticationError) {
          if (error instanceof FederatedAuthenticationError && error.code === "VERIFICATION_UNAVAILABLE") throw new AppError("Provider verification is unavailable","FEDERATED_VERIFICATION_UNAVAILABLE",503);
          throw new AppError("Use an existing sign-in method belonging to this account","REAUTHENTICATION_REJECTED",401);
        }
        if (error instanceof EmailAlreadyInUseError) throw new AppError("This email cannot be connected", "EMAIL_LINK_CONFLICT", 409);
        if (error instanceof InvalidPasswordError || error instanceof InvalidEmailError) throw new AppError("Check the email and password requirements", "INVALID_ACCOUNT_DETAILS", 400);
        if (error instanceof EmailSecurityRateLimitError) throw new AppError("Please wait before trying again", "RATE_LIMITED", 429);
        if (error instanceof TrustedIdentityAppError) throw new AppError("Application is not registered", "IDENTITY_APP_INVALID", 400);
        throw error;
      }
    };
    function input<T>(schema: z.ZodType<T>, body: unknown) {
      const parsed = schema.safeParse(body);
      if (!parsed.success) throw new AppError("Invalid account request", "INVALID_REQUEST", 400);
      return parsed.data;
    }
    app.post("/account/reauthenticate/email",request=>handle(request,async(m,s)=>{
      const p=input(z.object({email:z.string().max(320),password:z.string().min(1).max(128)}).strict(),request.body);
      const expected=await m.reauthenticationHuman(s,request.ip);
      return {session:await services.login.execute(p,expected)};
    }));
    app.post("/account/reauthenticate/:provider",request=>handle(request,async(m,s)=>{
      const p=input(z.object({provider:z.enum(["apple","google"])}).strict(),request.params);
      const proof=input(z.object({identityToken:z.string().min(1).max(16384),nonce:z.string().regex(/^[A-Za-z0-9_-]{32,256}$/u)}).strict(),request.body);
      const expected=await m.reauthenticationHuman(s,request.ip);
      const result=await services.authenticateFederated.executeExisting({...proof,provider:p.provider},expected);
      return {session:result.session,account:{email:result.providerEmail}};
    }));
    app.get("/account", request => handle(request, (m, s) => m.summary(s)));
    app.post("/account/email/connect", request => handle(request, (m, s) => {
      const value = input(z.object({ email: z.string().max(320), password: z.string().min(12).max(128), appId: z.string().min(1).max(64).optional() }).strict(), request.body);
      return m.connectEmail(s, { email:value.email,password:value.password,...(value.appId===undefined?{}:{appId:value.appId}), ipAddress: request.ip });
    }));
    app.delete("/account/email", request => handle(request, (m, s) => {
      input(z.object({}).strict(), request.body ?? {});
      return m.disconnectEmail(s);
    }));
    app.post("/account/password/change", request => handle(request, (m, s) => {
      const value = input(z.object({ currentPassword: z.string().min(1).max(128), password: z.string().min(12).max(128) }).strict(), request.body);
      return m.changePassword(s, value.currentPassword, value.password, request.ip);
    }));
  };
}
