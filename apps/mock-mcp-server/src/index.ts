import { MOCK_SERVER_PORT } from "@aegis/protocol";
import { buildApp } from "./app.js";

const { server } = buildApp();

server.listen(MOCK_SERVER_PORT, "127.0.0.1", () => {
  console.log(`mock-mcp-server listening at http://127.0.0.1:${MOCK_SERVER_PORT}/mcp`);
});
