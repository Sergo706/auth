import type { Configuration }  from "../types/configSchema.js";
import { configurationSchema } from "../types/configSchema.js";
import z from "zod";

let cfg: Configuration | undefined;

// // @ts-check
// main routes and middlewares// The ones that make the lib usable, the "Default"
/**
 * @description
 * The JWT auth library’s configuration object.
 * Contains the core configuration to make the library usable.
 *  
 * @module jwtAuth/config
 * @see {@link ./jwtAuth/types/configSchema.js}
 */
export function configuration(config: Configuration): void {
  try {
    const sch = configurationSchema.parse(config);
    cfg = Object.freeze(sch);        
  } catch(err) {
    if (err instanceof z.ZodError) {
          err.issues.forEach(issue => {
          const key = issue.path[0] as string
          throw new Error(`Configuration: The provided configuration is not valid ${key} Error - ${issue.message}`);
    })
    } else {
      throw new Error(`Configuration: Please configure the library properly ${err}`);
   }
  }
}


export function getConfiguration(): Configuration {
  if (!cfg) {
    console.trace("Premature getConfiguration() call");
    throw new Error(`##### Must be called once #####
      Auth System: configuration() must be called once in top level app start-up`
    );
  }
  return cfg;
};
