import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.connect((err, client, release) => {
  if (err) {
    return console.error('Database connection error:', err.stack);
  }
  console.log('Successfully connected to the PostgreSQL cloud database!');
  if (release) release();
});

export default pool;