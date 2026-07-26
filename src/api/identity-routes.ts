import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";

import { EmailAlreadyInUseError, InvalidEmailError, InvalidPasswordError } from "../authentication/credentials/domain/errors.js";
import { InvalidLoginError } from "../operations/application/errors.js";
import type { IdentityServices } from "./services.js";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";

const credentialsSchema = z.object({
  email: z.string(),
  password: z.string(),
});

export function identityRoutes(
  services: IdentityServices,
): FastifyPluginAsync {
  return async (app) => {
    app.post("/register", async (request, reply) => {
      const input = parseCredentials(request.body);
      try {
        const result = await services.register.execute(input);
        return reply.status(201).send(result);
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

    app.post("/logout", async (request, reply) => {
      const sessionId = bearerSessionId(request);
      await services.logout.execute(sessionId);
      return reply.status(204).send();
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
