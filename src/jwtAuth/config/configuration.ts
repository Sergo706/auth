import { AuthConfig } from "../types/config.js";

let cfg: AuthConfig | undefined;

export function configuration(config: AuthConfig): void {
if (!config.store || !config.telegram || !config.jwt || !config.email || !config.password || !config.logLevel ||!config.magic_links)          
     throw new Error('AuthConfig: Please configure the library properly');
     cfg = Object.freeze(config);   
}


export function getConfiguration(): AuthConfig {
  if (!cfg) {
    throw new Error(
      'Auth System: configuration() must be called once in app start-up'
    );
  }
  return cfg;
};
