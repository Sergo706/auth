import { Resend } from 'resend';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ejs from "ejs";
import { getConfiguration } from '../config/configuration.js';
import { getLogger } from './logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


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
    variables?: {
       variableOne: string;
       variableTwo: string;
       variableThree: string;
    }[]
    images?: {
        path: string;
        name: string;
        alt: string;
     }[]
}
/**
 * @description
 * Sends emails via your SMTP provider.
 *
 * @param {string | string[]} recipients
 *   One or more recipient email addresses.
 * @param {string} subject
 *   The subject line for the email.
 * @param {import('./systemEmails.js').EmailData} userData
 *   The data to populate the email template (see `EmailData` in `systemEmails.js`).
 * @param {string} template
 *   The name of the email template to use.
 *
 * @returns {Promise<void>}
 *   Resolves when the email has been sent (or throws on failure).
 *
 * @see {@link ./systemEmails.js}
 *
 * @example
 * import { EmailData } from './systemEmails.js';
 *
 * const data: EmailData = {
 *   name: 'Alice',
 *   resetLink: 'https://example.com/reset?token=xyz'
 * };
 *
 * await sendSystemEmail(
 *   ['alice@example.com', 'bob@example.com'],
 *   'Welcome to Our Service!',
 *   data,
 *   'welcomeTemplate'
 * );
 */
export async function sendSystemEmail(
    recipients: string[] | string,
     subject: string, 
     userData: EmailData, 
     template: string,
    ): Promise<void> {
    const log = getLogger().child({service: 'auth', branch: 'utils', type: 'sendSystemEmail'})
    let html: string;
    const toField = Array.isArray(recipients) ? recipients : [recipients];
    const { email } = getConfiguration();
    const resend = new Resend(email.resend_key);
    const renderData = {
        ...userData
    }

 try {
        const filePath = path.join(__dirname, '..', "emails", `${template}.ejs`)
        html = await ejs.renderFile(filePath, renderData)
   } catch(err) {
         log.error(`Failed to render template '${template}.ejs':`, err);
         throw err;
   }

  const { data, error } = await resend.emails.send({
    from: email.email,
    to: toField,
    subject: subject,
    html: html,
  });

  if (error) {
    return log.error( error );
  }

  log.info(" Email sent:", data);
}





