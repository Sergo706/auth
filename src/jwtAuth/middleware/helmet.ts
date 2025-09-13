import helmet, { HelmetOptions } from "helmet";

const options: HelmetOptions = {
  crossOriginEmbedderPolicy: true,
  
  xFrameOptions: { 
    action: "deny" 
  },
  contentSecurityPolicy: { 
    directives: {
      "frame-ancestors": ["'none'"],
    }
  },
  referrerPolicy: {
    policy: "origin",
  },
};

export default helmet(options);