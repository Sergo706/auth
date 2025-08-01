import z, { ZodType } from "zod/v4";
import { getConfiguration } from "../config/configuration.js";

export const StandardProfileSchema = z.object({
  sub: z.string(),
  email: z.email().optional(),
  email_verified: z.boolean().optional(),
  name: z.string().optional(),
  given_name: z.string().optional(),
  family_name: z.string().optional(),
  last_name: z.string().optional(),
  avatar: z.url({protocol: /^https$/, hostname: z.regexes.domain, normalize: true}).optional(),
  locale: z.string().optional(),
});

export type StandardProfile = z.infer<typeof StandardProfileSchema>;

export interface ProviderConfig<Schema extends ZodType> {
  name: string;
  schema: Schema;
  mapProfile(raw: z.infer<Schema>): StandardProfile;
}

interface ProviderInput<Schema extends ZodType = ZodType> {
  name: string;
  schema: Schema;
};

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
    const data = raw;
    return {
      sub: (data as any).sub as string,        
      email: (data as any).email,
      email_verified: Boolean((data as any).email_verified),
      name: (data as any).given_name, 
      given_name: (data as any).given_name,  
      family_name: (data as any).family_name,
      last_name: (data as any).last_name,
      avatar: (data as any).picture ?? (data as any).avatar,
      locale: (data as any).locale,          
    };
  }
}


function mapProvider<Schema extends ZodType>(config: ProviderInput<Schema>): OAuthProvider<Schema> {
  const provider = new Provider<Schema>(config.name, config.schema)
  return {
    provider,
    mapProfile: provider.mapProfile.bind(provider) as (raw: z.infer<Schema>) => StandardProfile
  }
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
export function getProviders(newProviders?: ProviderInput<ZodType>[]): OAuthProvider<ZodType>[] {
      const raw = newProviders ?? getConfiguration().providers ?? [];      
      return  raw.map((p) => mapProvider(p));
} 
