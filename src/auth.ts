import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { createAuthEndpoint, openAPI } from "better-auth/plugins";
import { db } from "./db";
import * as authSchema from "./db/auth-schema";

const providers = [
	"apple",
	"atlassian",
	"cognito",
	"discord",
	"dropbox",
	"facebook",
	"figma",
	"github",
	"gitlab",
	"google",
	"huggingface",
	"kakao",
	"kick",
	"line",
	"linear",
	"linkedin",
	"microsoft",
	"naver",
	"notion",
	"paybin",
	"paypal",
	"polar",
	"reddit",
	"roblox",
	"salesforce",
	"slack",
	"spotify",
	"tiktok",
	"twitch",
	"twitter",
	"vercel",
	"vk",
	"zoom",
];

export const configuredProviders = providers.reduce<
	Record<
		string,
		{
			clientId?: string;
			clientSecret?: string;
			appBundleIdentifier?: string;
			tenantId?: string;
			requireSelectAccount?: boolean;
			clientKey?: string;
			issuer?: string;
			domain?: string;
			region?: string;
			userPoolId?: string;
			environment?: string;
			team?: string;
			authority?: string;
			requestShippingAddress?: boolean;
			loginUrl?: string;
			redirectUri?: string;
			permissions?: number; // specify type number or bitwise value
			scopes?: string[];
			fields?: string[];
			prompt?: string;
			accessType?: string;
			disabledDefaultScope?: boolean;
			scope?: string[];
			duration?: string;
		}
	>
>((acc, provider) => {
	const id = process.env[`${provider.toUpperCase()}_CLIENT_ID`];
	const secret = process.env[`${provider.toUpperCase()}_CLIENT_SECRET`];
	if (!Object.keys(acc).includes(provider)) {
		acc[provider] = {
			clientId: id,
			clientSecret: secret,
		};
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
	if (provider === "google" && acc[provider]) {
		const prompt = process.env[`${provider.toUpperCase()}_PROMPT`];
		const accessType = process.env[`${provider.toUpperCase()}_ACCESS_TYPE`];
		if (accessType && accessType.length > 0) {
			acc[provider].accessType = accessType;
		}
		if (prompt && prompt.length > 0) {
			acc[provider].prompt = prompt;
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
	if (provider === "cognito" && acc[provider]) {
		const domain = process.env[`${provider.toUpperCase()}_DOMAIN`];
		const region = process.env[`${provider.toUpperCase()}_REGION`];
		const userPoolId = process.env[`${provider.toUpperCase()}_USERPOOL_ID`];
		if (domain && domain.length > 0) {
			acc[provider].domain = domain;
		}
		if (region && region.length > 0) {
			acc[provider].region = region;
		}
		if (userPoolId && userPoolId.length > 0) {
			acc[provider].userPoolId = userPoolId;
		}
	}
	if (provider === "facebook" && acc[provider]) {
		const scopes = process.env[`${provider.toUpperCase()}_SCOPES`];
		const fields = process.env[`${provider.toUpperCase()}_FIELDS`];
		if (scopes && scopes.length > 0) {
			acc[provider].scopes = scopes.split(",").map((s) => s.trim());
		}
		if (fields && fields.length > 0) {
			acc[provider].fields = fields.split(",").map((f) => f.trim());
		}
	}
	if (provider === "figma" && acc[provider]) {
		const clientKey = process.env[`${provider.toUpperCase()}_CLIENT_KEY`];
		if (clientKey && clientKey.length > 0) {
			acc[provider].clientKey = clientKey;
		}
	}
	if ((provider === "paypal" || provider === "salesforce") && acc[provider]) {
		const environment = process.env[`${provider.toUpperCase()}_ENVIRONMENT`];
		if (environment && environment.length > 0) {
			acc[provider].environment = environment;
		}
		if (provider === "paypal") {
			const requestShippingAddress =
				process.env[`${provider.toUpperCase()}_REQUEST_SHIPPING_ADDRESS`];
			if (requestShippingAddress && requestShippingAddress.length > 0) {
				acc[provider].requestShippingAddress =
					requestShippingAddress === "true";
			}
		}
		if (provider === "salesforce") {
			const loginUrl = process.env[`${provider.toUpperCase()}_LOGIN_URL`];
			const redirectUri = process.env[`${provider.toUpperCase()}_REDIRECT_URI`];
			if (loginUrl && loginUrl.length > 0) {
				acc[provider].loginUrl = loginUrl;
			}
			if (redirectUri && redirectUri.length > 0) {
				acc[provider].redirectUri = redirectUri;
			}
		}
	}
	if (provider === "slack" && acc[provider]) {
		const team = process.env[`${provider.toUpperCase()}_TEAM_ID`];
		if (team && team.length > 0) {
			acc[provider].team = team;
		}
	}
	if (provider === "microsoft" && acc[provider]) {
		const tenantId = process.env[`${provider.toUpperCase()}_TENANT_ID`];
		const authority = process.env[`${provider.toUpperCase()}_AUTHORITY`];
		const prompt = process.env[`${provider.toUpperCase()}_PROMPT`];
		if (tenantId && tenantId.length > 0) {
			acc[provider].tenantId = tenantId;
		}
		if (authority && authority.length > 0) {
			acc[provider].authority = authority;
		}
		if (prompt && prompt.length > 0) {
			acc[provider].prompt = prompt;
		}
	}
	if (provider === "discord" && acc[provider]) {
		const permissions = process.env[`${provider.toUpperCase()}_PERMISSIONS`];
		if (permissions && permissions.length > 0) {
			// Should convert the string to a number or bitwise value
			acc[provider].permissions = permissions
				.split(",")
				.map(Number)
				.reduce((acc, val) => acc | val, 0);
		}
	}
	if (provider === "line" && acc[provider]) {
		const redirectUri = process.env[`${provider.toUpperCase()}_REDIRECT_URI`];
		const scope = process.env[`${provider.toUpperCase()}_SCOPE`];
		const disableDefaultScope =
			process.env[`${provider.toUpperCase()}_DISABLE_DEFAULT_SCOPE`];
		if (redirectUri && redirectUri.length > 0) {
			acc[provider].redirectUri = redirectUri;
		}
		if (scope && scope.length > 0) {
			acc[provider].scope = scope.split(",").map((s) => s.trim());
		}
		if (disableDefaultScope && disableDefaultScope.length > 0) {
			acc[provider].disabledDefaultScope = disableDefaultScope === "true";
		}
	}
	if (provider === "linear" && acc[provider]) {
		const scope = process.env[`${provider.toUpperCase()}_SCOPE`];
		if (scope && scope.length > 0) {
			acc[provider].scope = scope.split(",").map((s) => s.trim());
		}
	}
	if (provider === "reddit" && acc[provider]) {
		const duration = process.env[`${provider.toUpperCase()}_DURATION`];
		const scope = process.env[`${provider.toUpperCase()}_SCOPE`];
		if (duration && duration.length > 0) {
			acc[provider].duration = duration;
		}
		if (scope && scope.length > 0) {
			acc[provider].scope = scope.split(",").map((s) => s.trim());
		}
	}
	if (provider === "vercel" && acc[provider]) {
		const scope = process.env[`${provider.toUpperCase()}_SCOPE`];
		if (scope && scope.length > 0) {
			acc[provider].scope = scope.split(",").map((s) => s.trim());
		}
	}
	if (provider === "paybin" && acc[provider]) {
		const scope = process.env[`${provider.toUpperCase()}_SCOPE`];
		if (scope && scope.length > 0) {
			acc[provider].scope = scope.split(",").map((s) => s.trim());
		}
	}
	return acc;
}, {});

/**
 * Better-Auth Plugin that returns the list of available social providers
 *
 * Usage on client:
 * ```ts
 * const socialProvidersClient = () =>
 *	({
 *   	// $InferServerPlugin: {} as ReturnType<typeof socialProviders> # optional helper for type inference
 *		getActions: ($fetch) => {
 *			return {
 *				getSocialProviders: async (fetchOptions?: BetterFetchOption) => {
 *					const res = $fetch("/social-providers", {
 *						method: "GET",
 *						...fetchOptions,
 *					});
 *					return res.then((res) => res.data as string[]);
 *				},
 *			};
 *		},
 *		id: "social-providers-client",
 *	}) satisfies BetterAuthClientPlugin;
 *
 * export const authClient = createAuthClient({
 *   plugins: [socialProvidersClient()],
 * });
 * ```
 *
 * @returns BetterAuthServerPlugin
 */
export const socialProviders = () => ({
	id: "social-providers-plugin",
	endpoints: {
		getSocialProviders: createAuthEndpoint(
			"/social-providers",
			{
				method: "GET",
				metadata: {
					openapi: {
						description: "Returns the list of available social providers",
						responses: {
							200: {
								description: "Success",
								content: {
									"application/json": {
										schema: {
											type: "array",
											items: {
												type: "string",
											},
											description: "List of available social providers",
										},
									},
								},
							},
						},
					},
				},
			},
			async (ctx) =>
				ctx.json(ctx.context.socialProviders.map((p) => p.name.toLowerCase())),
		),
	},
});

export const auth = betterAuth({
	baseURL: process.env.BETTER_AUTH_URL || "http://localhost:8558",
	secret: process.env.BETTER_AUTH_SECRET || undefined,
	socialProviders: configuredProviders,
	emailAndPassword: {
		enabled: true,
		autoSignIn: true,
		minPasswordLength: 8,
	},
	plugins: [openAPI(), socialProviders()],
	trustedOrigins: [
		process.env.BETTER_AUTH_URL || "http://localhost:8558",
		...(process.env.ALLOWED_ORIGINS?.split(",") || []),
	],
	database: drizzleAdapter(db, {
		provider: "sqlite",
		schema: authSchema,
	}),
});
