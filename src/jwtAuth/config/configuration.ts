import { AuthConfig } from "../types/config.js";

let cfg: AuthConfig | undefined;

// // @ts-check
// main routes and middlewares// The ones that make the lib usable, the "Default"
/**
 * @description
 * The JWT auth library’s configuration object.
 * Contains the core configuration to make the library usable.
 *  
 * @module jwtAuth/config
 * @see {@link ./jwtAuth/types/config.js}
 */
export function configuration(config: AuthConfig): void {
if (!config.store || !config.telegram || !config.jwt || !config.email || !config.password || !config.logLevel ||!config.magic_links) {         
     throw new Error('AuthConfig: Please configure the library properly');
}
     cfg = Object.freeze(config);        
}


export function getConfiguration(): AuthConfig {
  if (!cfg) {
    console.trace("Premature getConfiguration() call");
    throw new Error(`…must be called once…
      Auth System: configuration() must be called once in app start-up`
    );
  }
  return cfg;
};
