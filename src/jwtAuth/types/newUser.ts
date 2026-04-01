import { NewUser } from "../models/zodSignUpSchemas.js";
import { StandardProfile } from "../utils/newOauthProvider.js";

export interface User extends NewUser  {
    country: string | null;
    city: string  | null;
    district: string  | null;
    visitor_id: string;
    
}
export interface OauthUser extends StandardProfile    {
    country: string | null;
    city: string  | null;
    district: string  | null;
    visitor_id: string;
    
}



