import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { openAPI } from "better-auth/plugins";
import { db } from "./db";
import * as authSchema from "./db/auth-schema";

const providers = [
	"apple",
	"discord",
	"dropbox",
	"facebook",
	"github",
	"gitlab",
	"google",
	"linkedin",
	"microsoft",
	"reddit",
	"roblox",
	"spotify",
	"tiktok",
	"twitch",
	"vk",
	"zoom",
	"x",
];

export const configuredProviders = providers.reduce<
	Record<
		string,
		{
			clientId: string;
			clientSecret: string;
			appBundleIdentifier?: string;
			tenantId?: string;
			requireSelectAccount?: boolean;
			clientKey?: string;
			issuer?: string;
		}
	>
>((acc, provider) => {
	const id = process.env[`${provider.toUpperCase()}_CLIENT_ID`];
	const secret = process.env[`${provider.toUpperCase()}_CLIENT_SECRET`];
	if (id && id.length > 0 && secret && secret.length > 0) {
		acc[provider] = { clientId: id, clientSecret: secret };
	}
	if (provider === "apple" && acc[provider]) {
		const bundleId =
			process.env[`${provider.toUpperCase()}_APP_BUNDLE_IDENTIFIER`];
		if (bundleId && bundleId.length > 0) {
			acc[provider].appBundleIdentifier = bundleId;
		}
	}
	if (provider === "gitlab" && acc[provider]) {
		const issuer = process.env[`${provider.toUpperCase()}_ISSUER`];
		if (issuer && issuer.length > 0) {
			acc[provider].issuer = issuer;
		}
	}
	if (provider === "microsoft" && acc[provider]) {
		acc[provider].tenantId = "common";
		acc[provider].requireSelectAccount = true;
	}
	if (provider === "tiktok" && acc[provider]) {
		const key = process.env[`${provider.toUpperCase()}_CLIENT_KEY`];
		if (key && key.length > 0) {
			acc[provider].clientKey = key;
		}
	}
	return acc;
}, {});

export const auth = betterAuth({
	baseURL: process.env.BETTER_AUTH_URL || "http://localhost:8558",
	secret: process.env.BETTER_AUTH_SECRET || undefined,
	socialProviders: configuredProviders,
	emailAndPassword: {
		enabled: true,
		autoSignIn: true,
		minPasswordLength: 8,
	},
	plugins: [openAPI()],
	trustedOrigins: process.env.ALLOWED_ORIGINS?.split(",") || [],
	database: drizzleAdapter(db, {
		provider: "sqlite",
		schema: authSchema,
	}),
});
