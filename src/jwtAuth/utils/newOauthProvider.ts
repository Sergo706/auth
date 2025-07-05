import z, { ZodType } from "zod/v4";
import { getConfiguration } from "../config/configuration.js";


export type StandardProfile = {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  last_name: string;
  avatar?: string;
  locale?: string;
};

export interface ProviderConfig<Schema extends ZodType> {
  name: string;
  schema: Schema;
  mapProfile(raw: z.infer<Schema>): StandardProfile;
}


class Provider<Schema extends ZodType> implements ProviderConfig<Schema> {
  constructor(
    public name: string,
    public schema: Schema
  ) {}

  mapProfile(raw: z.infer<Schema>): StandardProfile {
    const data = this.schema;
    return {
      sub: (data as any).id as string,        
      email: (data as any).email,
      name: (data as any).name,
      avatar: (data as any).picture,
      family_name: (data as any).family_name,
      last_name: (data as any).last_name,
      locale: (data as any).locale,
      email_verified: Boolean((data as any).email_verified),            
    };
  }
}


function mapProvider<Schema extends ZodType>(config: ProviderConfig<Schema>) {
  const provider = new Provider<Schema>(config.name, config.schema)
  return {
    provider,
    mapProfile: provider.mapProfile.bind(provider) as (raw: z.infer<Schema>) => StandardProfile
  }
}

export function getProviders(override?: ProviderConfig<ZodType>[]) {
      const raw = override ?? getConfiguration().providers ?? [];      
      return  raw.map((p) => mapProvider(p));

}
