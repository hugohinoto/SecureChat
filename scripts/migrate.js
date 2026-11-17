import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pool } from "../server/db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const migrationsDirectory = path.resolve(__dirname, "../database/migrations");

async function migrate() {
  const client = await pool.connect();

  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const files = (await readdir(migrationsDirectory))
      .filter((name) => /^\d+_[a-z0-9_-]+\.sql$/i.test(name))
      .sort();

    for (const name of files) {
      const alreadyApplied = await client.query(
        "SELECT 1 FROM schema_migrations WHERE name = $1",
        [name]
      );

      if (alreadyApplied.rowCount > 0) {
        console.log(`Already applied: ${name}`);
        continue;
      }

      const sql = await readFile(path.join(migrationsDirectory, name), "utf8");
      await client.query("BEGIN");

      try {
        await client.query(sql);
        await client.query(
          "INSERT INTO schema_migrations (name) VALUES ($1)",
          [name]
        );
        await client.query("COMMIT");
        console.log(`Applied: ${name}`);
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    }

    console.log("Database migrations complete.");
  } finally {
    client.release();
    await pool.end();
  }
}

migrate().catch(async (error) => {
  console.error("Database migration failed:", error.message);
  await pool.end().catch(() => {});
  process.exitCode = 1;
});
