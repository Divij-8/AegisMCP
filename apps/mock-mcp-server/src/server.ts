import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod/v4";
import { MOCK_SERVER_NAME, MOCK_SERVER_VERSION } from "@aegis/protocol";

export function createMockServer(): McpServer {
  const server = new McpServer({
    name: MOCK_SERVER_NAME,
    version: MOCK_SERVER_VERSION,
  });

  server.registerTool(
    "echo",
    {
      description: "Echoes the input message back to the caller",
      inputSchema: z.object({
        message: z.string(),
      }),
    },
    async ({ message }) => ({
      content: [{ type: "text", text: message }],
    }),
  );

  return server;
}
