import mysql2 from 'mysql2/promise';
import { dbConfig } from '../configs/config.js';


export async function createTestUser(email: string = 'test@example.com'): Promise<number> {
  const mainPool = await mysql2.createConnection(dbConfig);
  
  try {
    const [existingUsers] = await mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return existingUsers[0].id;
    }

    const visitorUuid = crypto.randomUUID(); 
    const canaryId = `test-canary-${Date.now()}-${Math.random()}`;


     await mainPool.execute(
      'INSERT INTO visitors (visitor_id, canary_id, ip_address, user_agent) VALUES (?, ?, ?, ?)',
      [visitorUuid, canaryId, '127.0.0.1', 'test-user-agent']
    );

    const [userResult] = await mainPool.execute<mysql2.ResultSetHeader>(
      'INSERT INTO users (name, last_name, email, password_hash, visitor_id) VALUES (?, ?, ?, ?, ?)',
      ['John', 'Doe', email, 'test-password-hash', visitorUuid] 
    );


    return userResult.insertId;
  } finally {
    await mainPool.end();
  }
  
}

export async function deleteUser(id?: number | string, email?: string) {
  if (!id && !email) throw new Error('Provide a user identifier to delete')

   const mainPool = await mysql2.createConnection(dbConfig);
  try{
    const query = `DELETE FROM users WHERE ${id ? "id" : "email"} = ?`;
    await mainPool.execute(query, [id ?? email]);
  } catch(err) {
    throw err;
  }finally {
    await mainPool.end();
  }
}