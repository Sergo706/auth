import fs from 'node:fs/promises';
import path from 'node:path';
import { getRoot, resolvePath } from '@riavzon/utils/server';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = getRoot(__dirname)
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
    
    const dirPath = resolvePath('', [
            'emails',
            'dist/emails', 
            'src/jwtAuth/emails'
    ], [], root);

    try {
        const pathToWrite = path.join(dirPath, name);


        if (existsSync(pathToWrite)) {
            throw new Error(`This template already exists: ${name}`);
        }

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

    const fullPath = resolvePath('', [
        'emails',
        'dist/emails', 
        'src/jwtAuth/emails'
    ], [], root);

    try {
       const files = await fs.readdir(fullPath, { recursive: true });
       console.log(files)
       return files;     
    } catch (err: any) {
        throw new Error(`Failed to list templates in ${fullPath}: ${err.message}`);
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
    const name = `${templateName}.ejs`;

    const pathToDelete = resolvePath(name, [
            'emails',
            'dist/emails', 
            'src/jwtAuth/emails'
    ], [], root);

    try {
        await fs.rm(pathToDelete)
    } catch (err: any) {
        throw new Error(`Error deleting template: ${err.message}`);
    }
}
