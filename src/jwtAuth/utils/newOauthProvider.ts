import z, { ZodType } from "zod/v4";
import { getConfiguration } from "../config/configuration.js";
import { makeSanitizedZodString } from "../../main.js";

export const StandardProfileSchema = z.object({
  sub: z.union([z.string(), z.number()]).optional(),
  id: z.union([z.string(), z.number()]).optional(),
  user_id: z.union([z.string(), z.number()]).optional(),
  email: z.email(),
  email_verified: z.boolean().optional(),
  name: z.string().optional(),
  given_name: z.string().optional(),
  family_name: z.string().optional(),
  last_name: z.string().optional(),
  avatar: z.url({protocol: /^https$/, hostname: z.regexes.domain, normalize: true}).optional(),
  avatar_url: z.url({protocol: /^https$/, hostname: z.regexes.domain, normalize: true}).optional(),
  picture: z.url({protocol: /^https$/, hostname: z.regexes.domain, normalize: true}).optional(),
  picture_url: z.url({protocol: /^https$/, hostname: z.regexes.domain, normalize: true}).optional(),
  locale: z.string().optional(),
  location: z.string().optional(),

}).refine(userId => Boolean(userId.sub || userId.id || userId.user_id), {
message: 'One of sub | id | user_id is required',
path: ['sub'],
});

export type StandardProfile = z.infer<typeof StandardProfileSchema>;

export interface ProviderConfig<Schema extends ZodType> {
  name: string;
  schema: Schema;
  mapProfile(raw: z.infer<Schema>): StandardProfile;
}

type JsonFieldToken =
  | 'string' | 'string?'
  | 'email'  | 'email?'
  | 'boolean'| 'boolean?'
  | 'url'    | 'url?'
  | 'number' | 'number?'
  | 'int'    | 'int?'
  | 'safeString' | 'safeString?';

export interface JsonProviderSpec {
  name: string;
  useStandardProfile?: boolean;
  fields?: Record<string, JsonFieldToken>;
}

interface ProviderInput<Schema extends ZodType = ZodType> {
  name: string;
  schema: Schema;
};

type AnyProviderSpec = ProviderInput<ZodType> | JsonProviderSpec;

interface OAuthProvider<Schema extends ZodType = ZodType> {
  provider: Provider<Schema>;
  mapProfile: (raw: z.infer<Schema>) => StandardProfile;
};


class Provider<Schema extends ZodType> implements ProviderConfig<Schema> {
  constructor(
    public name: string,
    public schema: Schema
  ) {}

  mapProfile(raw: z.infer<Schema>): StandardProfile {
    const data = raw as any;
    const userId = String(data.sub ?? data.id ?? data.user_id)
    return {
      sub: userId,     
      email: data.email,
      email_verified: Boolean(data.email_verified),
      name: data.name ?? data.given_name, 
      given_name: data.given_name,  
      family_name: data.family_name,
      last_name: data.last_name,
      avatar: data.picture ?? data.picture_url ?? data.avatar ?? data.avatar_url,
      locale: data.locale ?? data.location,          
    };
  }
}


function buildSchemaFromFields(fields?: Record<string, JsonFieldToken>, useStandard?: boolean): ZodType {
  if (useStandard || !fields) return StandardProfileSchema;

  const shape: Record<string, ZodType> = {};
  const makeOptional = (type: ZodType, optional: boolean) => optional ? type.optional() : type;

  const tokenToZod = (token: JsonFieldToken): ZodType => {
    const optional = token.endsWith('?');
    const base = token.replace('?', '');

    switch (base) {
      case 'string': return makeOptional(z.string(), optional);
      case 'safeString': return makeOptional(makeSanitizedZodString({min: 0, max: 300}), optional)
      case 'email': return makeOptional(z.email(), optional);
      case 'boolean':return makeOptional(z.boolean(), optional);
      case 'url': return makeOptional(z.url(), optional);
      case 'number': return makeOptional(z.number(), optional);
      case 'int': return makeOptional(z.int(), optional);
      default: return makeOptional(z.unknown(), optional);
    }
  };

  for (const [key, tok] of Object.entries(fields)) {
    shape[key] = tokenToZod(tok);
  }

  return z.object(shape);
}


function mapProvider(config: AnyProviderSpec): OAuthProvider<ZodType> {
  const hasSchema = (spec: AnyProviderSpec): spec is ProviderInput<ZodType> => { return 'schema' in spec; }

  const schema = hasSchema(config) ? config.schema : buildSchemaFromFields(config.fields, config.useStandardProfile);

  const provider = new Provider(config.name, schema);
  return {
    provider,
    mapProfile: provider.mapProfile.bind(provider) as (raw: any) => StandardProfile,
  };
}

/**
 * @description
 * Retrieves and instantiates all OAuth providers defined in your application configuration,
 * and optionally registers additional provider(s) passed as an argument.
 * If `newProviders` is provided, those configs are registered first.
 *
 * @function configureOauthProviders
 * @param {ProviderInput[]} [newProviders]
 *   An array of provider configs to register [name, ZodSchema]
 *   before returning the full list.
 * @returns {OAuthProvider[]}
 *   An array of instantiated OAuthProvider objects, including any newly registered ones.
 * @see {@link ./newOauthProvider.js}
 * @example
 * // 1 Use only configured providers:
 * const providers = configureOauthProviders();
 *
 * // 2 Register one extra provider on the fly:
 * import { customConfig } from './myCustomProvider';
 * const providersWithCustom = configureOauthProviders(customConfig);
 *
 * // 3 Register multiple extras:
 * import { googleConfig, facebookConfig } from './oauthConfigs';
 * const allProviders = configureOauthProviders([googleConfig, facebookConfig]);
 */
export function getProviders(newProviders?: AnyProviderSpec[]): OAuthProvider<ZodType>[] {
  const raw = newProviders ?? (getConfiguration().providers as AnyProviderSpec[] | undefined) ?? [];
  return raw.map((p) => mapProvider(p));
}
