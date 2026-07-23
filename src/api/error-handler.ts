import type { FastifyInstance } from "fastify";

import { AppError } from "../shared/errors.js";

export function setErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof AppError) {
      request.log.warn({ err: error }, "Request failed");

      return reply.status(error.statusCode).send({
        error: {
          code: error.code,
          message: error.message,
        },
      });
    }

    request.log.error({ err: error }, "Unhandled request error");

    return reply.status(500).send({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "An unexpected error occurred",
      },
    });
  });
}
