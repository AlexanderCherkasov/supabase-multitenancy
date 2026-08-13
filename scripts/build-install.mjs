import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDir = join(packageRoot, "sql", "migrations");
const files = readdirSync(migrationsDir).filter((file) => /^\d+_.+\.sql$/.test(file)).sort();
const body = files.map((file) => `-- BEGIN ${file}\n${readFileSync(join(migrationsDir, file), "utf8").trim()}\n-- END ${file}`).join("\n\n");
writeFileSync(
  join(packageRoot, "sql", "install.sql"),
  `-- Generated release artifact. Do not edit; edit sql/migrations instead.\n-- supabase-multitenancy v0.2.0\n\n${body}\n`,
);
