import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

const useSSL = (process.env.MYSQL_SSL ?? 'true').toLowerCase() === 'true';

export const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  port: Number(process.env.MYSQL_PORT ?? 3306),
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: useSSL ? { rejectUnauthorized: false } : undefined,
});

export async function pingDb(): Promise<void> {
  const conn = await pool.getConnection();
  try {
    await conn.ping();
  } finally {
    conn.release();
  }
}
