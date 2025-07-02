import { NewUser } from "../models/zodSignUpSchemas.js";
import { NewUserGoogle } from "../models/zodSchemaGoogle.js";

export interface User extends NewUser  {
    country: string | null;
    city: string  | null;
    district: string  | null;
    visitor_id: number;
    
}
export interface OauthUser extends NewUserGoogle   {
    country: string | null;
    city: string  | null;
    district: string  | null;
    visitor_id: number;
    
}



