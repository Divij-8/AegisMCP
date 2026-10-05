import { MOCK_SERVER_PORT } from "@aegis/protocol";
import { buildApp } from "./app.js";

const { server } = buildApp();

// Defaults to loopback (local dev/tests). Containers set MOCK_SERVER_HOST=0.0.0.0
// so a sibling container can reach it.
const host = process.env.MOCK_SERVER_HOST ?? "127.0.0.1";

server.listen(MOCK_SERVER_PORT, host, () => {
  console.log(`mock-mcp-server listening at http://${host}:${MOCK_SERVER_PORT}/mcp`);
});
