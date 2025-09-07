import pino from "pino";


type Result =
  | { valid: true }
  | { valid: false; errorType: "MalformedPayload" | "InvalidRoles" };

const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === "string");

const hasDuplicates = (arr: string[]) => new Set(arr).size !== arr.length;




export function compareRoles(requiredRaw: unknown, providedRaw: unknown, log: pino.Logger, {
    normalizer = (s: string) => s.trim(),
}: { normalizer?: (s: string) => string } = {} ): Result {


  if (!isStringArray(requiredRaw) || !isStringArray(providedRaw)) {
    log.error({ required: requiredRaw, provided: providedRaw }, "Malformed roles payload");
    return { valid: false, errorType: "MalformedPayload" };
  }


  if (hasDuplicates(requiredRaw) || hasDuplicates(providedRaw)) {
    log.error({ required: requiredRaw, provided: providedRaw }, "Duplicate roles in payload");
    return { valid: false, errorType: "MalformedPayload" };
  }

    const required = requiredRaw.map(normalizer);
    const provided = providedRaw.map(normalizer);

    if (hasDuplicates(required) || hasDuplicates(provided)) {
        log.error({ required, provided }, "Duplicate roles after normalization");
        return { valid: false, errorType: "MalformedPayload" };
    }

      const R = new Set(required);
      const P = new Set(provided);


        const missing = [...R].filter((r) => !P.has(r));
        const extras  = [...P].filter((r) => !R.has(r));


        if (missing.length > 0 || extras.length > 0) {
            log.error({ required, provided, missing, extras }, "Roles mismatch");
            return { valid: false, errorType: "InvalidRoles" };
        }

    return {valid: true}
}