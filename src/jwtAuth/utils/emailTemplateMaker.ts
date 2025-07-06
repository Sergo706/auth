import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * @description
 * Generate a custom ejs template.
 *
 * @param {string} html
 * the html to use in the template, you can fully use ejs syntax.
 *
 * @param {string} templateName
 *   the template name.
 *  @type {import('./systemEmails.js').EmailData}
 * @example
 *  * await sendSystemEmail(
 *   ['alice@example.com', 'bob@example.com'],
 *   'subject',
 *    data: EmailData,
 *   'yourTemplateName'
 * );
 * await makeEmailTemplate(`<p>template</p>`, `name`);
 * await sendSystemEmail(your)
 * @see {@link https://github.com/mde/ejs}
 * @see {@link ('./systemEmails.js').EmailData}
*/
export async function makeEmailTemplate(html: string, templateName: string) {
    const name = `${templateName}.ejs`;
    const filePath = path.join(__dirname, '..', 'emails');

    try {
        const files = await fs.readdir(filePath, { recursive: true });

        if (files.includes(name)) {
            throw new Error(`This template already exists: ${name}`);
        }

        const pathToWrite = path.join(filePath, name);
        await fs.appendFile(pathToWrite, html);
    } catch (err: any) {
        throw new Error(`Unexpected error creating a new template: ${err?.message || err}`);
    }
}

/**
 * @description
 * List all templates.
 *
 * @returns {string[]} files names in array.
 * @example
 *  listTemplates()
 * 
*/
export async function listTemplates() {
    const filePath = path.join(__dirname, '..', 'emails');
    try {
      const files = await fs.readdir(filePath, {recursive: true})
       console.log(files)
       return files;     
    } catch (err: any) {
        throw new Error(`Unexpected error creating a new template: ${err?.message || err}`);
    }
     
}
/**
 * @description
 * Delete a custom ejs template.
 *
 * @param {string} templateName
 *   the template name.
 * @example
 *  await deleteTemplate(templateName)
 * 
*/
export async function deleteTemplate(templateName: string) {
    const filePath = path.join(__dirname, '..', 'emails');
    const name = `${templateName}.ejs`;
    const pathToDelete = path.join(filePath, name);
    try {
        await fs.rm(pathToDelete)
    } catch (err: any) {
        throw new Error(`Unexpected error creating a new template: ${err?.message || err}`);
    }
}
