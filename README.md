# Simple MCP Server

Prototype MCP server built with TypeScript, Express, and `@modelcontextprotocol/sdk` (v1.29.0).

## Features

- Public tool: `get-country-prefix` (country code -> phone prefix)
- Protected tool: `get-countries-by-prefix` (phone prefix -> countries)
- In-memory login endpoint with fake users
- In-memory token/session auth (prototype only)

## Fake Users

- `admin` / `admin123`
- `user` / `user123`

## Run

```bash
npm install
npm run dev
```

Server defaults to `http://localhost:3000`.

## Endpoints

- `POST /auth/login` -> returns bearer token
- `POST /mcp`, `GET /mcp`, `DELETE /mcp` -> MCP Streamable HTTP endpoint

## Login Example

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\"}"
```

Use `Authorization: Bearer <access_token>` in MCP requests to access the protected tool.
