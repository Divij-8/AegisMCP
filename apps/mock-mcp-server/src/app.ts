import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { toWebRequest } from "@modelcontextprotocol/node";
import { createHandler } from "./handler.js";

export function buildApp() {
  const handler = createHandler();

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.url === "/mcp") {
      const webRequest = await toWebRequest(req);
      const webResponse = await handler.fetch(webRequest);

      res.writeHead(webResponse.status, Object.fromEntries(webResponse.headers));
      const body = await webResponse.arrayBuffer();
      res.end(Buffer.from(body));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  return { server, mcpHandler: handler };
}
