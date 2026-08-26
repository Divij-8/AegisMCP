import { createMcpHandler } from "@modelcontextprotocol/server";
import { createMockServer } from "./server.js";

export function createHandler() {
  return createMcpHandler(() => createMockServer(), {
    legacy: "reject",
  });
}
