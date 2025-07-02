import fs from 'node:fs/promises';
import path from 'node:path';
import pino from 'pino';

const listCache = new Map<string, Set<string>>();

export async function isDisposable(addr: string, log: pino.Logger): Promise<boolean> {

  log.info(`Checking if email is disposable...`)

  const domain = addr.split('@')[1]?.toLowerCase() ?? '';
  if (!domain) {
    log.warn('Invalid email supplied');
    return false;
  }

  const listPath = path.join(
    './',
    'disposable_email_blocklist.conf'
  );

  let blocked: Set<string>;
  if (listCache.has(listPath)) {
    blocked = listCache.get(listPath)!;
  } else {
    try {
      log.info('Reading disposable list...');
      const raw = await fs.readFile(listPath, 'utf-8');
      blocked = new Set(raw.split(/\r?\n/).map(l => l.trim().toLowerCase()).filter(Boolean));
      listCache.set(listPath, blocked);
    } catch (err) {
      log.error({ err }, 'Failed to read disposable list');
      return false;
    }
  }

  const isBlocked = blocked.has(domain);
  log.info(
    { domain, isBlocked },
    `Domain ${isBlocked ? 'is' : 'is NOT'} disposable`
  );
  return isBlocked;
}
