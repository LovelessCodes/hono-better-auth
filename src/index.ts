import { Hono } from "hono";
import { cors } from "hono/cors";
import "dotenv/config";
import { auth } from "./auth";

const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(",") || [];

const app = new Hono();

app.get("/", (c) => {
	return c.json({
		message: "Hello Hono x Better Auth!",
		description:
			"This is a simple example of a Hono x Better Auth application, you can use it as a starting point for your own application.",
		links: [
			{
				text: "Go to the Authentication API Documentation",
				href: new URL("/api/auth/reference", c.req.url).href,
			},
		],
	});
});

app.use(
	"/api/auth/**", // or replace with "*" to enable cors for all routes
	cors({
		origin: (origin, _) => {
			if (allowedOrigins.includes(origin)) {
				return origin;
			}
			return undefined;
		},
		allowHeaders: ["Content-Type", "Authorization"],
		allowMethods: ["POST", "GET", "OPTIONS"],
		exposeHeaders: ["Content-Length"],
		maxAge: 600,
		credentials: true,
	}),
);

app.on(["POST", "GET"], "/api/auth/**", (c) => {
	return auth.handler(c.req.raw);
});

export default {
	port: process.env.APP_PORT || 8558,
	host: process.env.APP_HOST || undefined,
	fetch: app.fetch,
};
