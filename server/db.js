import pg from "pg";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL is required. Configure PostgreSQL before starting SecureChat."
  );
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 8_000,
  keepAlive: true
});

pool.on("error", (error) => {
  // Never log connection strings or credentials.
  console.error("Unexpected PostgreSQL pool error:", error.message);
});
