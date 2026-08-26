import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { proxyMcpRequest, type McpProxyOptions } from "./mcp-proxy.js";

let upstream: http.Server;
let upstreamPort: number;
let proxyServer: http.Server;
let proxyPort: number;

function post(
  port: number,
  path: string,
  body: string,
  headers: Record<string, string>,
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        let data = "";
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers as Record<string, string>,
            body: data,
          });
        });
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

beforeAll(async () => {
  upstream = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      if (req.url === "/echo") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(body);
      } else if (req.url === "/error") {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "InternalError", message: "boom" }));
      } else if (req.url === "/slow") {
        setTimeout(() => {
          res.writeHead(200, { "content-type": "application/json" });
          res.end('{"ok":true}');
        }, 5000);
      } else if (req.url === "/headers") {
        res.writeHead(200, {
          "content-type": "application/json",
          "mcp-session-id": "test-session",
          connection: "keep-alive",
        });
        res.end(JSON.stringify({ headers: req.headers }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });
  });

  await new Promise<void>((resolve) => {
    upstream.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = upstream.address();
  if (!addr || typeof addr === "string") throw new Error("no address");
  upstreamPort = addr.port;

  proxyServer = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      const options: McpProxyOptions = {
        upstreamUrl: `http://127.0.0.1:${upstreamPort}${req.url ?? "/mcp"}`,
        upstreamTimeoutMs: 2000,
      };
      proxyMcpRequest(req, res, Buffer.from(body), options);
    });
  });

  await new Promise<void>((resolve) => {
    proxyServer.listen(0, "127.0.0.1", () => resolve());
  });
  const proxyAddr = proxyServer.address();
  if (!proxyAddr || typeof proxyAddr === "string") throw new Error("no proxy address");
  proxyPort = proxyAddr.port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    proxyServer.close(() => resolve());
  });
  await new Promise<void>((resolve) => {
    upstream.close(() => resolve());
  });
});

describe("proxyMcpRequest", () => {
  it("forwards request body to upstream", async () => {
    const payload = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "test" });
    const result = await post(proxyPort, "/echo", payload, {
      "content-type": "application/json",
    });

    expect(result.status).toBe(200);
    const parsed = JSON.parse(result.body) as Record<string, unknown>;
    expect(parsed).toHaveProperty("jsonrpc", "2.0");
    expect(parsed).toHaveProperty("method", "test");
  });

  it("returns upstream status code", async () => {
    const result = await post(proxyPort, "/error", "{}", {
      "content-type": "application/json",
    });

    expect(result.status).toBe(500);
    const parsed = JSON.parse(result.body) as Record<string, unknown>;
    expect(parsed).toHaveProperty("error", "InternalError");
  });

  it("returns 502 when upstream is unavailable", async () => {
    const deadProxy = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        proxyMcpRequest(req, res, Buffer.from(body), {
          upstreamUrl: "http://127.0.0.1:19999/mcp",
          upstreamTimeoutMs: 1000,
        });
      });
    });

    await new Promise<void>((resolve) => {
      deadProxy.listen(0, "127.0.0.1", () => resolve());
    });
    const deadAddr = deadProxy.address();
    if (!deadAddr || typeof deadAddr === "string") throw new Error("no addr");

    const result = await post(deadAddr.port, "/mcp", "{}", {
      "content-type": "application/json",
    });

    expect(result.status).toBe(502);
    const parsed = JSON.parse(result.body) as Record<string, unknown>;
    expect(parsed).toHaveProperty("error", "BadGateway");

    await new Promise<void>((resolve) => {
      deadProxy.close(() => resolve());
    });
  });

  it("returns 504 when upstream times out", async () => {
    const slowUpstream = http.createServer((_req, res) => {
      setTimeout(() => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"ok":true}');
      }, 5000);
    });

    await new Promise<void>((resolve) => {
      slowUpstream.listen(0, "127.0.0.1", () => resolve());
    });
    const slowAddr = slowUpstream.address();
    if (!slowAddr || typeof slowAddr === "string") throw new Error("no addr");

    const slowProxy = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        proxyMcpRequest(req, res, Buffer.from(body), {
          upstreamUrl: `http://127.0.0.1:${slowAddr.port}/slow`,
          upstreamTimeoutMs: 500,
        });
      });
    });

    await new Promise<void>((resolve) => {
      slowProxy.listen(0, "127.0.0.1", () => resolve());
    });
    const slowProxyAddr = slowProxy.address();
    if (!slowProxyAddr || typeof slowProxyAddr === "string") throw new Error("no addr");

    const result = await post(slowProxyAddr.port, "/slow", "{}", {
      "content-type": "application/json",
    });

    expect(result.status).toBe(504);
    const parsed = JSON.parse(result.body) as Record<string, unknown>;
    expect(parsed).toHaveProperty("error", "GatewayTimeout");

    await new Promise<void>((resolve) => {
      slowProxy.close(() => resolve());
    });
    await new Promise<void>((resolve) => {
      slowUpstream.close(() => resolve());
    });
  });

  it("forwards response headers from upstream", async () => {
    const result = await post(proxyPort, "/headers", "{}", {
      "content-type": "application/json",
    });

    expect(result.status).toBe(200);
    expect(result.headers["mcp-session-id"]).toBe("test-session");
  });

  it("filters hop-by-hop headers from upstream", async () => {
    const result = await post(proxyPort, "/headers", "{}", {
      "content-type": "application/json",
    });

    expect(result.status).toBe(200);
    expect(result.headers["proxy-authenticate"]).toBeUndefined();
    expect(result.headers["proxy-authorization"]).toBeUndefined();
  });

  it("forwards JSON response body with correct content-type", async () => {
    const payload = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "echo" });
    const result = await post(proxyPort, "/echo", payload, {
      "content-type": "application/json",
    });

    expect(result.status).toBe(200);
    expect(result.headers["content-type"]).toBe("application/json");
    const parsed = JSON.parse(result.body) as Record<string, unknown>;
    expect(parsed).toHaveProperty("method", "echo");
  });
});
