import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";

import { EmailAlreadyInUseError, InvalidEmailError, InvalidPasswordError } from "../authentication/credentials/domain/errors.js";
import { InvalidLoginError } from "../operations/application/errors.js";
import type { IdentityServices } from "./services.js";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";
import { FederatedAuthenticationError } from "../authentication/federated/application/errors.js";
import { FederatedAuthenticationMethodError } from "../authentication/federated/application/manage-federated-authentication-methods.js";
import { AppleAuthorizationCodeExchangeError } from "../authentication/federated/adapters/apple-authorization-code-exchanger.js";
import { GoogleAuthorizationCodeExchangeError } from "../authentication/federated/adapters/google-authorization-code-exchanger.js";
import { SessionRenewalError } from "../sessions/application/use-cases.js";
import {
  EmailActionTokenError,
  EmailSecurityRateLimitError,
  TrustedIdentityAppError,
} from "../authentication/email-security/application.js";

const credentialsSchema = z.object({
  email: z.string(),
  password: z.string(),
});
const federatedProviderSchema = z.object({
  provider: z.string().min(1).max(32),
});
const federatedCredentialSchema = z.object({
  identityToken: z.string().min(1).max(16_384),
  nonce: z.string().min(32).max(256),
}).strict();
const appleWebCredentialSchema = z.object({
  appId: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/u).optional(),
  authorizationCode: z.string().min(1).max(4_096),
  nonce: z.string().min(32).max(256),
}).strict();
const googleWebCredentialSchema = z.object({
  appId: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/u).optional(),
  authorizationCode: z.string().min(1).max(4_096),
  nonce: z.string().min(32).max(256),
  codeVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/u),
}).strict();
const sessionRenewalSchema = z.object({
  renewalToken: z.string().min(32).max(512),
}).strict();
const identityAppSchema = z.object({
  appId: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/u).optional(),
}).strict();
const forgotPasswordSchema = identityAppSchema.extend({
  email: z.string().min(1).max(320),
}).strict();
const emailActionTokenSchema = z.object({
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
}).strict();
const resetPasswordSchema = emailActionTokenSchema.extend({
  password: z.string().min(1).max(128),
}).strict();

export function identityRoutes(
  services: IdentityServices,
): FastifyPluginAsync {
  return async (app) => {
    app.post("/register", async (request, reply) => {
      const input = parseRegistration(request.body);
      try {
        await services.emailPasswordSecurity.guardRegistration(input.email, request.ip, input.appId);
        const result = await services.register.execute(input);
        let delivery: "sent" | "disabled" | "failed" = "failed";
        try {
          delivery = await services.emailPasswordSecurity.sendRegistrationVerification({
            email: input.email,
            ...(input.appId === undefined ? {} : { appId: input.appId }),
          });
        } catch {
          request.log.error("Registration completed but verification delivery preparation failed");
        }
        return reply.status(201).send({
          ...result,
          emailVerification: { required: true, delivery },
        });
      } catch (error) {
        throw translateRegistrationError(error);
      }
    });

    app.post("/login", async (request, reply) => {
      const input = parseCredentials(request.body);
      try {
        const session = await services.login.execute(input);
        return reply.send({ session });
      } catch (error) {
        if (error instanceof InvalidLoginError) {
          throw new AppError(
            "Invalid email or password",
            "INVALID_CREDENTIALS",
            401,
          );
        }
        throw error;
      }
    });

    app.post("/authentication/federated/:provider", async (request, reply) => {
      const provider = federatedProviderSchema.safeParse(request.params);
      const credential = federatedCredentialSchema.safeParse(request.body);
      if (!provider.success || !credential.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      try {
        const result = await services.authenticateFederated.execute({
          provider: provider.data.provider,
          ...credential.data,
        });
        return reply.send({
          session: result.session,
          account: { email: result.providerEmail },
        });
      } catch (error) {
        if (error instanceof FederatedAuthenticationError) {
          request.log.warn(
            { federatedFailureCode: error.code, provider: provider.data.provider },
            "Federated authentication rejected",
          );
        }
        throw translateFederatedAuthenticationError(error);
      }
    });

    app.post("/authentication/federated/apple/web", async (request, reply) => {
      const credential = appleWebCredentialSchema.safeParse(request.body);
      if (!credential.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      const authentication = credential.data.appId === undefined
        ? services.authenticateAppleWeb
        : services.webAuthenticationApps?.get(credential.data.appId)?.apple;
      if (authentication === undefined) {
        throw new AppError(
          "Apple web authentication is temporarily unavailable",
          "APPLE_WEB_AUTHENTICATION_UNAVAILABLE",
          503,
        );
      }
      try {
        const result = await authentication.execute({ authorizationCode: credential.data.authorizationCode, nonce: credential.data.nonce });
        return reply.send({
          session: result.session,
          account: { email: result.providerEmail },
        });
      } catch (error) {
        if (error instanceof AppleAuthorizationCodeExchangeError) {
          request.log.warn(
            { appleWebFailureCode: error.code },
            "Apple web authorization-code exchange rejected",
          );
          if (error.code === "TOKEN_EXCHANGE_UNAVAILABLE") {
            throw new AppError(
              "Apple web authentication is temporarily unavailable",
              "APPLE_WEB_AUTHENTICATION_UNAVAILABLE",
              503,
            );
          }
          throw new AppError(
            "The Apple authorization was not accepted",
            "APPLE_AUTHORIZATION_CODE_INVALID",
            401,
          );
        }
        throw translateFederatedAuthenticationError(error);
      }
    });

    app.post("/authentication/federated/google/web", async (request, reply) => {
      const credential = googleWebCredentialSchema.safeParse(request.body);
      if (!credential.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      const authentication = credential.data.appId === undefined
        ? services.authenticateGoogleWeb
        : services.webAuthenticationApps?.get(credential.data.appId)?.google;
      if (authentication === undefined) {
        throw new AppError(
          "Google web authentication is temporarily unavailable",
          "GOOGLE_WEB_AUTHENTICATION_UNAVAILABLE",
          503,
        );
      }
      try {
        const result = await authentication.execute({ authorizationCode: credential.data.authorizationCode, nonce: credential.data.nonce, codeVerifier: credential.data.codeVerifier });
        return reply.send({
          session: result.session,
          account: { email: result.providerEmail },
        });
      } catch (error) {
        if (error instanceof GoogleAuthorizationCodeExchangeError) {
          request.log.warn(
            { googleWebFailureCode: error.code },
            "Google web authorization-code exchange rejected",
          );
          if (error.code === "TOKEN_EXCHANGE_UNAVAILABLE") {
            throw new AppError(
              "Google web authentication is temporarily unavailable",
              "GOOGLE_WEB_AUTHENTICATION_UNAVAILABLE",
              503,
            );
          }
          throw new AppError(
            "The Google authorization was not accepted",
            "GOOGLE_AUTHORIZATION_CODE_INVALID",
            401,
          );
        }
        throw translateFederatedAuthenticationError(error);
      }
    });

    app.post("/authentication/federated/:provider/resolve", async (request, reply) => {
      const provider = federatedProviderSchema.safeParse(request.params);
      const credential = federatedCredentialSchema.safeParse(request.body);
      if (!provider.success || !credential.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      try {
        return reply.send(await services.resolveFederatedIdentity.execute({
          provider: provider.data.provider,
          ...credential.data,
        }));
      } catch (error) {
        throw translateFederatedAuthenticationError(error);
      }
    });

    app.get("/authentication/methods", async (request, reply) => {
      try {
        const methods = await services.federatedAuthenticationMethods.list(bearerSessionId(request));
        return reply.send({ methods });
      } catch (error) {
        throw translateAuthenticationMethodsError(error);
      }
    });

    app.get("/authentication/email-password", async (request, reply) => {
      const sessionId = bearerSessionId(request);
      const validation = await services.validateSession.execute(sessionId);
      if (validation.outcome !== "authenticated") {
        throw new AppError("Session is not authenticated", `SESSION_${validation.outcome.toUpperCase()}`, 401);
      }
      return reply.send(await services.emailPasswordSecurity.authenticationState(sessionId.value));
    });

    app.post("/email-verification/resend", async (request, reply) => {
      const input = identityAppSchema.safeParse(request.body ?? {});
      if (!input.success) throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      try {
        await services.emailPasswordSecurity.resendVerification({
          sessionId: bearerSessionId(request).value,
          ipAddress: request.ip,
          ...(input.data.appId === undefined ? {} : { appId: input.data.appId }),
        });
      } catch (error) {
        if (error instanceof TrustedIdentityAppError) {
          throw new AppError("Invalid application", "IDENTITY_APP_INVALID", 400);
        }
        throw error;
      }
      return reply.status(202).send({
        message: "If verification is still needed, delivery has been requested.",
        deliveryAvailable: services.emailPasswordSecurity.emailDeliveryAvailable,
      });
    });

    app.post("/email-verification/verify", async (request, reply) => {
      const input = emailActionTokenSchema.safeParse(request.body);
      if (!input.success) throw invalidEmailActionToken();
      try {
        await services.emailPasswordSecurity.verifyEmail(input.data.token, request.ip);
        return reply.status(204).send();
      } catch (error) {
        throw translateEmailActionError(error);
      }
    });

    app.post("/password/forgot", async (request, reply) => {
      const input = forgotPasswordSchema.safeParse(request.body);
      if (!input.success) throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      try {
        await services.emailPasswordSecurity.requestPasswordReset({
          email: input.data.email,
          ipAddress: request.ip,
          ...(input.data.appId === undefined ? {} : { appId: input.data.appId }),
        });
      } catch (error) {
        if (error instanceof TrustedIdentityAppError) {
          throw new AppError("Invalid application", "IDENTITY_APP_INVALID", 400);
        }
        throw error;
      }
      return reply.status(202).send({
        message: "If an eligible account exists, reset instructions have been requested.",
        deliveryAvailable: services.emailPasswordSecurity.emailDeliveryAvailable,
      });
    });

    app.post("/password/reset", async (request, reply) => {
      const input = resetPasswordSchema.safeParse(request.body);
      if (!input.success) throw new AppError("Reset details are invalid", "INVALID_PASSWORD_RESET", 400);
      try {
        await services.emailPasswordSecurity.resetPassword({
          token: input.data.token,
          plaintextPassword: input.data.password,
          ipAddress: request.ip,
        });
        return reply.status(204).send();
      } catch (error) {
        if (error instanceof InvalidPasswordError) {
          throw new AppError("Use a password between 12 and 128 characters", "INVALID_PASSWORD", 400);
        }
        throw translateEmailActionError(error);
      }
    });

    app.post("/authentication/federated/:provider/link", async (request, reply) => {
      const provider = federatedProviderSchema.safeParse(request.params);
      const credential = federatedCredentialSchema.safeParse(request.body);
      if (!provider.success || !credential.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      try {
        return reply.send(await services.federatedAuthenticationMethods.link(
          bearerSessionId(request),
          { provider: provider.data.provider, ...credential.data },
        ));
      } catch (error) {
        throw translateAuthenticationMethodsError(error);
      }
    });

    app.delete("/authentication/federated/:provider/link", async (request, reply) => {
      const provider = federatedProviderSchema.safeParse(request.params);
      if (!provider.success) {
        throw new AppError("Invalid provider", "INVALID_REQUEST", 400);
      }
      try {
        return reply.send(await services.federatedAuthenticationMethods.unlink(
          bearerSessionId(request),
          provider.data.provider,
        ));
      } catch (error) {
        throw translateAuthenticationMethodsError(error);
      }
    });

    app.post("/products/grocery-master/apple-revocation", async (request, reply) => {
      const configured = services.groceryAppleRevocation;
      if (!configured) throw new AppError("Apple revocation is not configured", "APPLE_REVOCATION_UNAVAILABLE", 503);
      const supplied = request.headers["x-grocery-service-token"];
      if (typeof supplied !== "string" || !timingSafeEqual(createHash("sha256").update(supplied).digest(),
        createHash("sha256").update(configured.serviceToken).digest())) {
        throw new AppError("Service authorization required", "UNAUTHORIZED", 401);
      }
      const body = z.object({ principalId: z.string().min(1).max(200), operationId: z.string().uuid(),
        proof: z.object({ authorizationCode: z.string().min(1).max(4096), nonce: z.string().regex(/^[A-Za-z0-9_-]{32,256}$/) }).strict().optional(),
      }).strict().safeParse(request.body);
      if (!body.success) throw new AppError("Invalid deletion request", "INVALID_REQUEST", 400);
      await configured.service.execute(body.data.principalId, body.data.operationId, body.data.proof);
      return reply.status(204).send();
    });

    app.post("/logout", async (request, reply) => {
      const sessionId = bearerSessionId(request);
      await services.logout.execute(sessionId);
      return reply.status(204).send();
    });

    app.post("/session/refresh", async (request, reply) => {
      const input = sessionRenewalSchema.safeParse(request.body);
      if (!input.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      try {
        return reply.send({ session: await services.renewSession.execute(input.data.renewalToken) });
      } catch (error) {
        if (error instanceof SessionRenewalError) {
          throw new AppError(
            "Session cannot be renewed",
            `SESSION_RENEWAL_${error.reason.toUpperCase()}`,
            401,
          );
        }
        throw error;
      }
    });

    app.get("/session", async (request, reply) => {
      const sessionId = bearerSessionId(request);
      const result = await services.validateSession.execute(sessionId);
      if (result.outcome !== "authenticated") {
        throw new AppError(
          "Session is not authenticated",
          `SESSION_${result.outcome.toUpperCase()}`,
          401,
        );
      }
      return reply.send(result);
    });
  };
}

function translateAuthenticationMethodsError(error: unknown): Error {
  if (error instanceof FederatedAuthenticationError) {
    return translateFederatedAuthenticationError(error);
  }
  if (!(error instanceof FederatedAuthenticationMethodError)) {
    return error instanceof Error ? error : new Error("Authentication method operation failed");
  }
  if (error.code.startsWith("SESSION_")) {
    return new AppError("Session is not authenticated", error.code, 401);
  }
  if (error.code === "IDENTITY_UNAVAILABLE") {
    return new AppError("The Human Identity is unavailable", error.code, 403);
  }
  if (error.code === "FEDERATED_IDENTITY_LINK_CONFLICT") {
    return new AppError("A different provider identity is already connected", error.code, 409);
  }
  if (error.code === "FEDERATED_IDENTITY_RECONCILIATION_REQUIRED") {
    return new AppError("This provider identity belongs to another account and cannot be safely reconciled", error.code, 409);
  }
  return new AppError("The last authentication method cannot be removed", error.code, 409);
}

function translateFederatedAuthenticationError(error: unknown): Error {
  if (!(error instanceof FederatedAuthenticationError)) {
    return error instanceof Error ? error : new Error("Federated authentication failed");
  }
  if (error.code === "PROVIDER_UNSUPPORTED") {
    return new AppError("The federated identity provider is unsupported", "FEDERATED_PROVIDER_UNSUPPORTED", 400);
  }
  if (error.code === "VERIFICATION_UNAVAILABLE") {
    return new AppError("Federated authentication is temporarily unavailable", "FEDERATED_VERIFICATION_UNAVAILABLE", 503);
  }
  if (error.code === "IDENTITY_UNAVAILABLE" || error.code === "FEDERATED_IDENTITY_UNAVAILABLE") {
    return new AppError("Federated authentication is unavailable", "FEDERATED_AUTHENTICATION_UNAVAILABLE", 403);
  }
  if (error.code === "FEDERATED_IDENTITY_CONFLICT") {
    return new AppError("Federated authentication cannot be completed", "FEDERATED_IDENTITY_CONFLICT", 409);
  }
  return new AppError("The federated credential was not accepted", "FEDERATED_CREDENTIAL_INVALID", 401);
}

function parseCredentials(body: unknown): {
  email: string;
  password: string;
} {
  const parsed = credentialsSchema.safeParse(body);
  if (!parsed.success) {
    throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
  }
  return parsed.data;
}

function parseRegistration(body: unknown): {
  email: string;
  password: string;
  appId?: string;
} {
  const parsed = credentialsSchema.extend({
    appId: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/u).optional(),
  }).strict().safeParse(body);
  if (!parsed.success) throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
  return {
    email: parsed.data.email,
    password: parsed.data.password,
    ...(parsed.data.appId === undefined ? {} : { appId: parsed.data.appId }),
  };
}

function bearerSessionId(request: FastifyRequest): SessionId {
  const authorization = request.headers.authorization;
  const match = /^Bearer ([^\s]+)$/.exec(authorization ?? "");
  if (match?.[1] === undefined) {
    throw new AppError(
      "A bearer session is required",
      "SESSION_INVALID",
      401,
    );
  }
  return SessionId.from(match[1]);
}

function translateRegistrationError(error: unknown): Error {
  if (error instanceof TrustedIdentityAppError) {
    return new AppError("Invalid application", "IDENTITY_APP_INVALID", 400);
  }
  if (error instanceof EmailSecurityRateLimitError) {
    return new AppError("Please wait before trying again", "RATE_LIMITED", 429);
  }
  if (error instanceof EmailAlreadyInUseError) {
    return new AppError(
      "An account cannot be created with these details",
      "REGISTRATION_UNAVAILABLE",
      409,
    );
  }
  if (error instanceof InvalidEmailError || error instanceof InvalidPasswordError) {
    return new AppError(
      "Registration details are invalid",
      "INVALID_REGISTRATION_DETAILS",
      400,
    );
  }
  return error instanceof Error ? error : new Error("Registration failed");
}

function invalidEmailActionToken(): AppError {
  return new AppError(
    "This link is invalid, expired, or has already been used",
    "EMAIL_ACTION_TOKEN_INVALID",
    400,
  );
}

function translateEmailActionError(error: unknown): Error {
  if (error instanceof EmailActionTokenError) return invalidEmailActionToken();
  if (error instanceof EmailSecurityRateLimitError) {
    return new AppError("Please wait before trying again", "RATE_LIMITED", 429);
  }
  return error instanceof Error ? error : new Error("Email security action failed");
}
