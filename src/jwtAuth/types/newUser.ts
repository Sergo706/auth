import { NewUser } from "../models/zodSignUpSchemas.js";
import { NewUserGoogle } from "../models/zodSchemaGoogle.js";
import { StandardProfile } from "../utils/newOauthProvider.js";

export interface User extends NewUser  {
    country: string | null;
    city: string  | null;
    district: string  | null;
    visitor_id: number;
    
}
export interface OauthUser extends StandardProfile    {
    country: string | null;
    city: string  | null;
    district: string  | null;
    visitor_id: number;
    
}



