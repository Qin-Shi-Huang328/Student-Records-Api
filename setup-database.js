// Runs database.sql against the database in DATABASE_URL.
// Safe to run more than once: every statement is idempotent.
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. Add it to .env before running database setup.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function setupDatabase() {
  try {
    const schema = fs.readFileSync(path.join(__dirname, 'database.sql'), 'utf8');
    await pool.query(schema);
    console.log('Database schema is ready.');
  } catch (error) {
    console.error('Database setup failed:', error.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

setupDatabase();