# AegisMCP

A zero-trust security gateway for AI-agent tool execution.

## Structure

```
aegis-mcp/
├── apps/
│   ├── gateway/          — Fastify HTTP gateway
│   └── mock-mcp-server/ — Mock MCP server for testing
├── packages/
│   └── protocol/         — Shared types and constants
└── tests/
    └── integration/      — Cross-package integration tests
```

## Development

```bash
pnpm install
pnpm run dev
```

## Quality

```bash
pnpm run check
```

This runs typecheck, lint, format check, and tests in sequence.
