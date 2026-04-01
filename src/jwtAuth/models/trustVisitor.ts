import { updateVisitors } from "@riavzon/bot-detector";
import { FingerPrint } from "../types/fingerprint.js";
import { getPool } from '../config/configuration.js';
import type { ResultSetHeader } from "mysql2";
import pino from "pino";

export async function trustVisitor(userId: number, visitorIdToTrust: string, canaryId: string, fingerprints: FingerPrint, log: pino.Logger): Promise<{
    ok: boolean,
    date: string
    data: string | unknown
}> {
    const conn = await getPool().getConnection()
    log.info(`Mapping user's visitor data...`)
    try {
        await conn.beginTransaction();
        await conn.execute<ResultSetHeader>(`
            UPDATE users
            JOIN visitors
                ON visitors.visitor_id = ?
            SET
                users.visitor_id = visitors.visitor_id
            WHERE
                users.id = ?
            `,
        [visitorIdToTrust, userId]    
    );
        log.info(`user visitor id updated, trusting new fingerprints...`)
     
        const fingerPrint = await updateVisitors({
                userAgent: fingerprints.userAgent,
                ipAddress: fingerprints.ipAddress,
                country: fingerprints.country ?? '',
                region: fingerprints.region ?? '',
                regionName: fingerprints.regionName ?? '',
                city: fingerprints.city ?? '',
                district: fingerprints.district ?? '',
                lat: fingerprints.lat ?? '',
                lon: fingerprints.lon ?? '',
                timezone: fingerprints.timezone ?? '',
                currency: fingerprints.currency ?? '',
                isp: fingerprints.isp ?? '',
                org: fingerprints.org ?? '',
                as: fingerprints.as_org ?? '',
                device_type: fingerprints.device,
                browser: fingerprints.browser ?? '',
                proxy: fingerprints.proxy ?? false,
                hosting: fingerprints.hosting ?? false,
                deviceVendor: fingerprints.deviceVendor ?? '',
                deviceModel: fingerprints.deviceModel ?? '',
                browserType: fingerprints.browserType ?? '',
                browserVersion: fingerprints.browserVersion ?? '',
                os: fingerprints.os ?? ''
            },
            canaryId,
            visitorIdToTrust
        )
        if (!fingerPrint.success) {
            log.info(`failed to update fingerprints`)
            conn.rollback()
            return {
                ok: false,
                date: new Date().toISOString(),
                data: `Failed to trust user. ${fingerPrint.reason}`
            }
        }
        conn.commit()
        log.info(`Trusting new user fingerprints and visitor id!`)
        return {
            ok: true,
            date: new Date().toISOString(),
            data: `User is trusted.`
        }
    } catch (err) {
        conn.rollback()
        return {
                ok: false,
                date: new Date().toISOString(),
                data: `Failed to trust user.`
            }
    }  finally {
         conn.release();
    }

}
