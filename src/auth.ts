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

type ProviderConfig = {
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
	permissions?: number;
	scopes?: string[];
	fields?: string[];
	prompt?: string;
	accessType?: string;
	disabledDefaultScope?: boolean;
	scope?: string[];
	duration?: string;
};

const getEnv = (provider: string, key: string) =>
	process.env[`${provider.toUpperCase()}_${key}`];

const parseList = (value: string | undefined) =>
	value ? value.split(",").map((s) => s.trim()) : undefined;

export const configuredProviders = providers.reduce<
	Record<string, ProviderConfig>
>((acc, provider) => {
	const env = (key: string) => getEnv(provider, key);

	const config: ProviderConfig = {
		clientId: env("CLIENT_ID"),
		clientSecret: env("CLIENT_SECRET"),
	};

	switch (provider) {
		case "apple":
			if (env("APP_BUNDLE_IDENTIFIER"))
				config.appBundleIdentifier = env("APP_BUNDLE_IDENTIFIER");
			break;
		case "gitlab":
			if (env("ISSUER")) config.issuer = env("ISSUER");
			break;
		case "google":
			if (env("ACCESS_TYPE")) config.accessType = env("ACCESS_TYPE");
			if (env("PROMPT")) config.prompt = env("PROMPT");
			break;
		case "microsoft":
			if (env("TENANT_ID")) config.tenantId = env("TENANT_ID");
			if (env("AUTHORITY")) config.authority = env("AUTHORITY");
			if (env("PROMPT")) config.prompt = env("PROMPT");
			break;
		case "tiktok":
		case "figma":
			if (env("CLIENT_KEY")) config.clientKey = env("CLIENT_KEY");
			break;
		case "cognito":
			if (env("DOMAIN")) config.domain = env("DOMAIN");
			if (env("REGION")) config.region = env("REGION");
			if (env("USERPOOL_ID")) config.userPoolId = env("USERPOOL_ID");
			break;
		case "facebook":
			if (env("SCOPES")) config.scopes = parseList(env("SCOPES"));
			if (env("FIELDS")) config.fields = parseList(env("FIELDS"));
			break;
		case "paypal":
			if (env("ENVIRONMENT")) config.environment = env("ENVIRONMENT");
			if (env("REQUEST_SHIPPING_ADDRESS"))
				config.requestShippingAddress =
					env("REQUEST_SHIPPING_ADDRESS") === "true";
			break;
		case "salesforce":
			if (env("ENVIRONMENT")) config.environment = env("ENVIRONMENT");
			if (env("LOGIN_URL")) config.loginUrl = env("LOGIN_URL");
			if (env("REDIRECT_URI")) config.redirectUri = env("REDIRECT_URI");
			break;
		case "slack":
			if (env("TEAM_ID")) config.team = env("TEAM_ID");
			break;
		case "discord":
			if (env("PERMISSIONS"))
				config.permissions =
					env("PERMISSIONS")
						?.split(",")
						.map(Number)
						.reduce((a, v) => a | v, 0) ?? undefined;
			break;
		case "line":
			if (env("REDIRECT_URI")) config.redirectUri = env("REDIRECT_URI");
			if (env("SCOPE")) config.scope = parseList(env("SCOPE"));
			if (env("DISABLE_DEFAULT_SCOPE"))
				config.disabledDefaultScope = env("DISABLE_DEFAULT_SCOPE") === "true";
			break;
		case "linear":
		case "reddit":
		case "vercel":
		case "paybin":
			if (env("SCOPE")) config.scope = parseList(env("SCOPE"));
			if (provider === "reddit" && env("DURATION"))
				config.duration = env("DURATION");
	}

	if (Object.values(config).some((v) => v !== undefined)) acc[provider] = config;
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
