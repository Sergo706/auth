import { Resend } from 'resend';
import { config } from '../config/secret.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ejs from "ejs";



const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const resend = new Resend(config.email.resend);

export interface EmailData {
    userName: string;
    code?: number;
    message: string;
    headers: {
        headerOne: string;
        headerTwo?: string;
        headerTree?: string
    }
    link?: {
        label: string;
        path: string
    }[],
    images?: {
        path: string;
        name: string;
        alt: string;
     }[]
}

export async function sendSystemEmail(
    recipients: string[] | string,
     subject: string, 
     userData: EmailData, 
     template: string,
    ) {
    let html: string;
    const toField = Array.isArray(recipients) ? recipients : [recipients];
    const renderData = {
        ...userData
    }

 try {
        const filePath = path.join(__dirname, '..', '..', 'src', "views", "emails", `${template}.ejs`)
        html = await ejs.renderFile(filePath, renderData)
   } catch(err) {
         console.error(`Failed to render template '${template}.ejs':`, err);
         throw err;
   }

  const { data, error } = await resend.emails.send({
    from: 'noreply@riavzon.com',
    to: toField,
    subject: subject,
    html: html,
  });

  if (error) {
    return console.error( error );
  }

  console.log(" Email sent:", data);
}





