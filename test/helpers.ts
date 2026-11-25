import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import pg from "pg";
import type { ProbeConfig, Queryable } from "../src/types.js";

export interface TestDb {
  db: Queryable;
  label: string;
  close(): Promise<void>;
}

/**
 * A fresh database with the fixture loaded. Uses PGlite (Postgres compiled to
 * WebAssembly, no setup needed) unless DATABASE_URL points at a real server,
 * in which case a throwaway database is created and dropped.
 */
export async function freshDb(): Promise<TestDb> {
  const fixture = await readFile(new URL("./fixture.sql", import.meta.url), "utf8");
  const url = process.env.DATABASE_URL;
  if (!url) {
    const lite = new PGlite();
    await lite.exec(fixture);
    return { db: lite, label: "PGlite", close: () => lite.close() };
  }
  const admin = new pg.Client({ connectionString: url });
  await admin.connect();
  const name = `tenant_probe_${process.pid}_${Math.random().toString(36).slice(2, 8)}`;
  await admin.query(`create database ${name}`);
  const target = new URL(url);
  target.pathname = `/${name}`;
  const client = new pg.Client({ connectionString: target.toString() });
  await client.connect();
  await client.query(fixture);
  return {
    db: client,
    label: `PostgreSQL ${target.host}`,
    close: async () => {
      await client.end();
      await admin.query(`drop database ${name}`);
      await admin.end();
    },
  };
}

export async function fixtureConfig(): Promise<ProbeConfig> {
  return JSON.parse(await readFile(new URL("../examples/fixture.config.json", import.meta.url), "utf8")) as ProbeConfig;
}
