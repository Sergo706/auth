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
    const details = err.issues.map(issue => {
        const path     = issue.path.length ? issue.path.join(".") : "(root)";
        const received = JSON.stringify(issue.input);
        const code = issue.code
        return `• Path: ${path}\n  Message: ${issue.message}\n  Received: ${received}\n Code: ${code}\n`;
      }).join("\n");
       const pretty = z.prettifyError(err)
      throw new Error(`Configuration validation failed with ${err.issues.length} error(s):\n${details}\n Pretty Print: ${pretty}\n`);

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
