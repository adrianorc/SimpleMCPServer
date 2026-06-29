import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import { randomUUID } from "node:crypto";
import * as z from "zod/v4";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import {
    getOAuthProtectedResourceMetadataUrl,
    mcpAuthRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type {
    AuthorizationParams,
    OAuthServerProvider,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { InvalidRequestError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
    OAuthClientInformationFull,
    OAuthTokenRevocationRequest,
    OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

type User = {
    username: string;
    password: string;
};

type LoginSession = {
    username: string;
    expiresAt: number;
};

type AuthorizationCodeRecord = {
    clientId: string;
    username: string;
    codeChallenge: string;
    redirectUri: string;
    scopes: string[];
    resource?: URL;
    expiresAt: number;
};

type AccessTokenRecord = {
    clientId: string;
    username: string;
    scopes: string[];
    resource?: URL;
    expiresAt: number;
};

type RefreshTokenRecord = {
    clientId: string;
    username: string;
    scopes: string[];
    resource?: URL;
    expiresAt: number;
};

const PORT = Number(process.env.PORT ?? 3000);
const LOGIN_SESSION_COOKIE = "mcp_login_session";
const LOGIN_SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const AUTH_CODE_TTL_MS = 10 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000;
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// Prototype in-memory user store with fake credentials.
const users: User[] = [
    { username: "admin", password: "admin123" },
    { username: "user", password: "user123" },
];

const tlaToClientCode: Record<string, string> = {
    ABC: "8065666700",
    FRMS: "8070827783",
    EXLN: "8069887678",
    FTC: "8070846700",
};

const clientCodeToTla: Record<string, string> = Object.fromEntries(
    Object.entries(tlaToClientCode).map(([tla, code]) => [code, tla]),
);
const loginSessions = new Map<string, LoginSession>();
const sessionAuth = new Map<string, string>();
const transports = new Map<string, StreamableHTTPServerTransport>();
const authorizationCodes = new Map<string, AuthorizationCodeRecord>();
const accessTokens = new Map<string, AccessTokenRecord>();
const refreshTokens = new Map<string, RefreshTokenRecord>();

class InMemoryClientsStore implements OAuthRegisteredClientsStore {
    private readonly clients = new Map<string, OAuthClientInformationFull>();

    constructor(preRegisteredClients: OAuthClientInformationFull[]) {
        for (const client of preRegisteredClients) {
            this.clients.set(client.client_id, client);
        }
    }

    getClient(clientId: string): OAuthClientInformationFull | undefined {
        return this.clients.get(clientId);
    }

    registerClient(
        client: Omit<
            OAuthClientInformationFull,
            "client_id" | "client_id_issued_at"
        >,
    ): OAuthClientInformationFull {
        const nowSeconds = Math.floor(Date.now() / 1000);
        const registeredClient: OAuthClientInformationFull = {
            ...client,
            client_id: randomUUID(),
            client_secret: client.client_secret ?? randomUUID(),
            client_id_issued_at: nowSeconds,
            client_secret_expires_at: 0,
        };
        this.clients.set(registeredClient.client_id, registeredClient);
        return registeredClient;
    }
}

class InMemoryOAuthProvider implements OAuthServerProvider {
    readonly clientsStore: OAuthRegisteredClientsStore;

    constructor(clientsStore: OAuthRegisteredClientsStore) {
        this.clientsStore = clientsStore;
    }

    async authorize(
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
        res: Response,
    ): Promise<void> {
        const scopes = params.scopes ?? [];

        if (!client.redirect_uris.includes(params.redirectUri)) {
            throw new InvalidRequestError("Unregistered redirect_uri");
        }

        const request = res.req as Request | undefined;
        const username = request
            ? getAuthenticatedUsernameFromCookies(request)
            : undefined;

        if (!username) {
            const loginUrl = new URL("/login", getServerBaseUrl());
            loginUrl.searchParams.set("client_id", client.client_id);
            loginUrl.searchParams.set("redirect_uri", params.redirectUri);
            loginUrl.searchParams.set("code_challenge", params.codeChallenge);
            if (params.state) {
                loginUrl.searchParams.set("state", params.state);
            }
            if (params.resource) {
                loginUrl.searchParams.set(
                    "resource",
                    params.resource.toString(),
                );
            }
            if (scopes.length > 0) {
                loginUrl.searchParams.set("scope", scopes.join(" "));
            }
            res.redirect(loginUrl.toString());
            return;
        }

        const code = randomUUID();
        authorizationCodes.set(code, {
            clientId: client.client_id,
            username,
            codeChallenge: params.codeChallenge,
            redirectUri: params.redirectUri,
            scopes,
            resource: params.resource,
            expiresAt: Date.now() + AUTH_CODE_TTL_MS,
        });

        const redirectUrl = new URL(params.redirectUri);
        redirectUrl.searchParams.set("code", code);
        if (params.state) {
            redirectUrl.searchParams.set("state", params.state);
        }
        res.redirect(redirectUrl.toString());
    }

    async challengeForAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string,
    ): Promise<string> {
        const codeRecord = authorizationCodes.get(authorizationCode);
        if (!codeRecord || codeRecord.expiresAt <= Date.now()) {
            authorizationCodes.delete(authorizationCode);
            throw new Error("Invalid or expired authorization code");
        }
        if (codeRecord.clientId !== client.client_id) {
            throw new Error("Authorization code was not issued to this client");
        }
        return codeRecord.codeChallenge;
    }

    async exchangeAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string,
        _codeVerifier?: string,
        redirectUri?: string,
        resource?: URL,
    ): Promise<OAuthTokens> {
        const codeRecord = authorizationCodes.get(authorizationCode);
        if (!codeRecord || codeRecord.expiresAt <= Date.now()) {
            authorizationCodes.delete(authorizationCode);
            throw new Error("Invalid or expired authorization code");
        }
        if (codeRecord.clientId !== client.client_id) {
            throw new Error("Authorization code was not issued to this client");
        }
        if (redirectUri && codeRecord.redirectUri !== redirectUri) {
            throw new Error(
                "redirect_uri does not match the authorization request",
            );
        }
        if (
            resource &&
            codeRecord.resource &&
            resource.toString() !== codeRecord.resource.toString()
        ) {
            throw new Error(
                "resource does not match the authorization request",
            );
        }

        authorizationCodes.delete(authorizationCode);
        return this.issueTokens({
            clientId: client.client_id,
            username: codeRecord.username,
            scopes: codeRecord.scopes,
            resource: resource ?? codeRecord.resource,
        });
    }

    async exchangeRefreshToken(
        client: OAuthClientInformationFull,
        refreshToken: string,
        scopes?: string[],
        resource?: URL,
    ): Promise<OAuthTokens> {
        const refreshRecord = refreshTokens.get(refreshToken);
        if (!refreshRecord || refreshRecord.expiresAt <= Date.now()) {
            refreshTokens.delete(refreshToken);
            throw new Error("Invalid or expired refresh token");
        }
        if (refreshRecord.clientId !== client.client_id) {
            throw new Error("Refresh token was not issued to this client");
        }

        const nextScopes = scopes ?? refreshRecord.scopes;
        if (!isSubset(nextScopes, refreshRecord.scopes)) {
            throw new Error("Requested scopes exceed refresh token scopes");
        }

        return this.issueTokens({
            clientId: refreshRecord.clientId,
            username: refreshRecord.username,
            scopes: nextScopes,
            resource: resource ?? refreshRecord.resource,
            includeRefreshToken: false,
        });
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const tokenRecord = accessTokens.get(token);
        if (!tokenRecord || tokenRecord.expiresAt <= Date.now()) {
            accessTokens.delete(token);
            throw new Error("Invalid or expired access token");
        }

        return {
            token,
            clientId: tokenRecord.clientId,
            scopes: tokenRecord.scopes,
            expiresAt: Math.floor(tokenRecord.expiresAt / 1000),
            resource: tokenRecord.resource,
            extra: {
                username: tokenRecord.username,
            },
        };
    }

    async revokeToken(
        client: OAuthClientInformationFull,
        request: OAuthTokenRevocationRequest,
    ): Promise<void> {
        const accessRecord = accessTokens.get(request.token);
        if (accessRecord && accessRecord.clientId === client.client_id) {
            accessTokens.delete(request.token);
        }

        const refreshRecord = refreshTokens.get(request.token);
        if (refreshRecord && refreshRecord.clientId === client.client_id) {
            refreshTokens.delete(request.token);
        }
    }

    private issueTokens(input: {
        clientId: string;
        username: string;
        scopes: string[];
        resource?: URL;
        includeRefreshToken?: boolean;
    }): OAuthTokens {
        const accessToken = randomUUID();
        const refreshToken = randomUUID();

        accessTokens.set(accessToken, {
            clientId: input.clientId,
            username: input.username,
            scopes: input.scopes,
            resource: input.resource,
            expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS,
        });

        if (input.includeRefreshToken !== false) {
            refreshTokens.set(refreshToken, {
                clientId: input.clientId,
                username: input.username,
                scopes: input.scopes,
                resource: input.resource,
                expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
            });
        }

        return {
            access_token: accessToken,
            token_type: "bearer",
            expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
            refresh_token:
                input.includeRefreshToken === false ? undefined : refreshToken,
            scope: input.scopes.length > 0 ? input.scopes.join(" ") : undefined,
        };
    }
}

function isSubset(candidate: string[], source: string[]): boolean {
    const sourceSet = new Set(source);
    return candidate.every((value) => sourceSet.has(value));
}

function parseCookieHeader(
    cookieHeader: string | undefined,
): Record<string, string> {
    if (!cookieHeader) {
        return {};
    }

    const parsed: Record<string, string> = {};
    const pairs = cookieHeader.split(";");
    for (const pair of pairs) {
        const [rawKey, ...valueParts] = pair.trim().split("=");
        if (!rawKey || valueParts.length === 0) {
            continue;
        }
        parsed[rawKey] = decodeURIComponent(valueParts.join("="));
    }
    return parsed;
}

function getAuthenticatedUsernameFromCookies(req: Request): string | undefined {
    const cookies = parseCookieHeader(req.headers.cookie);
    const sessionId = cookies[LOGIN_SESSION_COOKIE];
    if (!sessionId) {
        return undefined;
    }

    const session = loginSessions.get(sessionId);
    if (!session) {
        return undefined;
    }

    if (session.expiresAt <= Date.now()) {
        loginSessions.delete(sessionId);
        return undefined;
    }

    return session.username;
}

function renderLoginPage(errorMessage?: string): string {
    const safeError = errorMessage
        ? `<p style="color:#b91c1c;">${errorMessage}</p>`
        : "";
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>MCP OAuth Login</title>
</head>
<body style="font-family: sans-serif; max-width: 560px; margin: 2rem auto;">
  <h1>Sign in</h1>
  <p>Authenticate to continue the OAuth authorization flow.</p>
  ${safeError}
  <form method="post" action="/login">
    <input type="hidden" name="client_id" value="" />
    <input type="hidden" name="redirect_uri" value="" />
    <input type="hidden" name="code_challenge" value="" />
    <input type="hidden" name="state" value="" />
    <input type="hidden" name="resource" value="" />
    <input type="hidden" name="scope" value="" />
    <div style="margin-bottom: 1rem;">
      <label for="username">Username</label><br />
      <input id="username" name="username" type="text" required />
    </div>
    <div style="margin-bottom: 1rem;">
      <label for="password">Password</label><br />
      <input id="password" name="password" type="password" required />
    </div>
    <button type="submit">Continue</button>
  </form>
  <script>
    const query = new URLSearchParams(window.location.search);
    for (const key of ["client_id","redirect_uri","code_challenge","state","resource","scope"]) {
      const input = document.querySelector('input[name="' + key + '"]');
      if (input) input.value = query.get(key) || "";
    }
  </script>
</body>
</html>`;
}

function getServerBaseUrl(): URL {
    //return new URL(" https://zdvbbcjgtx.a.pinggy.link");
    return new URL(process.env.ISSUER_URL ?? `http://localhost:${PORT}`);
}

function createServer(): McpServer {
    const server = new McpServer({
        name: "simple-mcp-server",
        version: "1.0.0",
    });

    server.registerTool(
        "get-client-code",
        {
            title: "Get Client Code",
            description:
                "Translates a TLA (three or four letter code) to its numeric Client Code.",
            inputSchema: {
                tla: z
                    .string()
                    .min(3)
                    .max(4)
                    .describe(
                        "A three or four letter code such as ABC, FRMS, EXLN, FTC",
                    ),
            },
        },
        async ({ tla }) => {
            const normalized = tla.toUpperCase();
            const clientCode = tlaToClientCode[normalized];

            if (!clientCode) {
                return {
                    isError: true,
                    content: [
                        {
                            type: "text",
                            text: `Invalid TLA: ${normalized}. Valid TLAs are: ${Object.keys(tlaToClientCode).join(", ")}`,
                        },
                    ],
                };
            }

            const structured = { tla: normalized, clientCode };
            return {
                content: [{ type: "text", text: JSON.stringify(structured) }],
                structuredContent: structured,
            };
        },
    );

    server.registerTool(
        "get-tla",
        {
            title: "Get TLA",
            description:
                "Translates a numeric Client Code back to its TLA (three or four letter code). Requires login.",
            inputSchema: {
                clientCode: z
                    .string()
                    .regex(/^\d+$/, "Client Code must be numeric"),
            },
        },
        async ({ clientCode }, extra) => {
            const sessionId = extra.sessionId;
            const authUser = sessionId ? sessionAuth.get(sessionId) : undefined;

            if (!authUser) {
                return {
                    isError: true,
                    content: [
                        {
                            type: "text",
                            text: "Authentication required. Login and call this tool with a bearer token.",
                        },
                    ],
                };
            }

            const tla = clientCodeToTla[clientCode];
            if (!tla) {
                return {
                    isError: true,
                    content: [
                        {
                            type: "text",
                            text: `TLA not found for Client Code: ${clientCode}`,
                        },
                    ],
                };
            }

            const structured = { clientCode, tla, requestedBy: authUser };
            return {
                content: [{ type: "text", text: JSON.stringify(structured) }],
                structuredContent: structured,
            };
        },
    );

    return server;
}

const allowedHosts = ["localhost", "127.0.0.1", "[::1]"];
if (process.env.ALLOWED_HOSTS) {
    for (const h of process.env.ALLOWED_HOSTS.split(",")) {
        const trimmed = h.trim();
        if (trimmed) allowedHosts.push(trimmed);
    }
}

const app = createMcpExpressApp({ allowedHosts });
app.use(
    cors({
        origin: "*",
        methods: ["GET", "POST", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization", "Mcp-Session-Id"],
        exposedHeaders: ["Mcp-Session-Id"],
    }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const baseUrl = getServerBaseUrl();
const mcpServerUrl = new URL("/mcp", baseUrl);
const preRegisteredClients: OAuthClientInformationFull[] = [
    {
        client_id: "mcp-test-client",
        client_secret: "mcp-test-secret",
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0,
        redirect_uris: [
            "http://127.0.0.1:8788/callback",
            "http://localhost:8788/callback",
        ],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post",
        scope: "mcp:tools",
    },
    {
        client_id: "chatgpt",
        client_secret: "chatgpt-secret",
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0,
        redirect_uris: ["https://chatgpt.com/connector/oauth/RiI3d50iVZkV"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post",
        scope: "mcp:tools",
    },
];
const clientsStore = new InMemoryClientsStore(preRegisteredClients);
const oauthProvider = new InMemoryOAuthProvider(clientsStore);

app.get("/login", (req: Request, res: Response) => {
    const hasRequiredParams =
        typeof req.query.client_id === "string" &&
        typeof req.query.redirect_uri === "string" &&
        typeof req.query.code_challenge === "string";

    if (!hasRequiredParams) {
        res.status(400).send("Missing required OAuth parameters.");
        return;
    }

    res.type("html").send(renderLoginPage());
});

app.post("/login", (req: Request, res: Response) => {
    const username = String(req.body?.username ?? "");
    const password = String(req.body?.password ?? "");

    const foundUser = users.find(
        (user) => user.username === username && user.password === password,
    );
    if (!foundUser) {
        res.status(401)
            .type("html")
            .send(renderLoginPage("Invalid credentials."));
        return;
    }

    const sessionId = randomUUID();
    loginSessions.set(sessionId, {
        username: foundUser.username,
        expiresAt: Date.now() + LOGIN_SESSION_TTL_MS,
    });

    res.cookie(LOGIN_SESSION_COOKIE, sessionId, {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: LOGIN_SESSION_TTL_MS,
        path: "/",
    });

    const authorizeUrl = new URL("/authorize", baseUrl);
    for (const field of [
        "client_id",
        "redirect_uri",
        "code_challenge",
        "state",
        "resource",
        "scope",
    ]) {
        const value = req.body?.[field];
        if (typeof value === "string" && value.length > 0) {
            authorizeUrl.searchParams.set(field, value);
        }
    }

    res.redirect(authorizeUrl.toString());
});

// Global logger middleware
app.use((req: Request, res: Response, next: NextFunction) => {
    const localTimeStamp = new Date().toISOString();

    console.log(
        `[AUDIT][${localTimeStamp}] ${req.method} ${req.url}, ` +
            `user-agent: ${req.headers["user-agent"]} ` +
            `content-type: ${req.headers["content-type"]} ` +
            `content-length: ${req.headers["content-length"]} ` +
            `auth: ${req.headers["authorization"]} ` +
            `mcp-session-id: ${req.headers["mcp-session-id"]} `,
    );
    next();
});

app.use(
    mcpAuthRouter({
        provider: oauthProvider,
        issuerUrl: baseUrl,
        resourceServerUrl: mcpServerUrl,
        scopesSupported: ["mcp:tools"],
        resourceName: "Simple MCP Server",
        authorizationOptions: { rateLimit: false },
        clientRegistrationOptions: { rateLimit: false },
        revocationOptions: { rateLimit: false },
        tokenOptions: { rateLimit: false },
    }),
);

const authMiddleware = requireBearerAuth({
    verifier: oauthProvider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
});

app.post("/mcp", authMiddleware, async (req: Request, res: Response) => {
    try {
        const sessionIdHeader = req.headers["mcp-session-id"];
        const sessionId =
            typeof sessionIdHeader === "string" ? sessionIdHeader : undefined;
        const authUsername =
            req.auth?.extra && typeof req.auth.extra.username === "string"
                ? req.auth.extra.username
                : undefined;

        if (sessionId && authUsername) {
            sessionAuth.set(sessionId, authUsername);
        }

        if (sessionId && transports.has(sessionId)) {
            const transport = transports.get(sessionId)!;
            await transport.handleRequest(req, res, req.body);
            return;
        }

        if (!sessionId && isInitializeRequest(req.body)) {
            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => randomUUID(),
                onsessioninitialized: (newSessionId) => {
                    transports.set(newSessionId, transport);
                },
            });

            transport.onclose = () => {
                if (transport.sessionId) {
                    transports.delete(transport.sessionId);
                    sessionAuth.delete(transport.sessionId);
                }
            };

            const server = createServer();
            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
            return;
        }

        res.status(400).json({
            jsonrpc: "2.0",
            error: {
                code: -32000,
                message: "Bad Request: Missing valid MCP session",
            },
            id: null,
        });
    } catch (error) {
        console.error("POST /mcp error:", error);
        if (!res.headersSent) {
            res.status(500).json({
                jsonrpc: "2.0",
                error: { code: -32603, message: "Internal server error" },
                id: null,
            });
        }
    }
});

app.get("/mcp", authMiddleware, async (req: Request, res: Response) => {
    const sessionIdHeader = req.headers["mcp-session-id"];
    const sessionId =
        typeof sessionIdHeader === "string" ? sessionIdHeader : undefined;

    if (!sessionId || !transports.has(sessionId)) {
        res.status(400).send("Invalid or missing session ID");
        return;
    }

    const transport = transports.get(sessionId)!;
    await transport.handleRequest(req, res);
});

app.delete("/mcp", authMiddleware, async (req: Request, res: Response) => {
    const sessionIdHeader = req.headers["mcp-session-id"];
    const sessionId =
        typeof sessionIdHeader === "string" ? sessionIdHeader : undefined;

    if (!sessionId || !transports.has(sessionId)) {
        res.status(400).send("Invalid or missing session ID");
        return;
    }

    const transport = transports.get(sessionId)!;
    await transport.handleRequest(req, res);
});

app.listen(PORT, (error?: Error) => {
    if (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
    console.log(`Simple MCP server running on http://localhost:${PORT}`);
    console.log(
        "OAuth metadata endpoint: /.well-known/oauth-authorization-server",
    );
    console.log("Authorization endpoint: /authorize");
    console.log("Token endpoint: /token");
    console.log("Dynamic client registration endpoint: /register");
    console.log("Login page endpoint: /login");
    console.log("MCP endpoint: /mcp");
});

process.on("SIGINT", async () => {
    for (const transport of transports.values()) {
        await transport.close();
    }
    process.exit(0);
});
