import mysql2 from 'mysql2/promise';
import mysql, { Pool } from 'mysql2'; 
import { getConfiguration } from './configuration.js';

let pool: mysql2.Pool;

export async function getPool() { 
  if (pool) return pool;
  const { store } = getConfiguration()

  try { 
  pool = mysql2.createPool ({
    host: store.host,
    port: store.port,
    user: store.user,
    password: store.password,
    database: store.databaseName,
    waitForConnections: true,      
    connectionLimit: store.connectionLimit,          
    queueLimit: store.queueLimit,             
    connectTimeout: store.connectTimeout,
  });
  console.log(`Connected to MySQL! to ${store.databaseName} as ${store.user}`);
} catch(err) {
  console.log(`Error connecting to MySQL`, err);
  throw err;
}
return pool;
}

let poolForLib: mysql.Pool;
export async function poolForLibary() { 
  if (pool) return pool;
  const { store } = getConfiguration()

  try { 
  poolForLib = mysql.createPool ({
    host: store.host,
    port: store.port,
    user: store.user,
    password: store.password,
    database: store.databaseName,
    waitForConnections: true,      
    connectionLimit: store.connectionLimit,          
    queueLimit: store.queueLimit,             
    connectTimeout: store.connectTimeout,
  }) as Pool;
  console.log(`Connected to MySQL! to ${store.databaseName} as ${store.user}`);
} catch(err) {
  console.log(`Error connecting to MySQL`, err);
  throw err;
}
return pool;
}