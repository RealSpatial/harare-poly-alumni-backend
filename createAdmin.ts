import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Connect to the database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const createAdmin = async () => {
  try {
    // UPDATED EMAIL AS REQUESTED
    const email = 'principal@hrepoly.ac.zw';
    const plainTextPassword = 'adminpassword123';

    // 1. Check if admin already exists
    const checkUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkUser.rows.length > 0) {
      console.log("Admin account already exists!");
      process.exit();
    }

    // 2. Encrypt the password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(plainTextPassword, salt);

    // 3. Insert into the database with the 'admin' role
    await pool.query(
      "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)",
      [email, passwordHash, 'admin']
    );

    console.log("SUCCESS! Principal admin account created.");
    console.log(`Email: ${email}`);
    console.log(`Password: ${plainTextPassword}`);
    
  } catch (error) {
    console.error("Failed to create admin:", error);
  } finally {
    pool.end();
  }
};

createAdmin();