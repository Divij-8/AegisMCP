/**
 * Public surface of the security layer.
 *
 * Consumed by the gateway composition root and by integration tests that need
 * to provision credentials. Nothing here imports Fastify or HTTP.
 */

export * from "./identity.js";
export * from "./rbac.js";
export * from "./credential.js";
export * from "./hash.js";
export * from "./authenticator.js";
export * from "./credential-service.js";
