#!/usr/bin/env node
import { access, appendFile, readFile, writeFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import pg from "pg";
import { ConfigError, normalizeConfig, starterConfig } from "./config.js";
import { probe } from "./probe.js";
import { exitCode, formatMarkdown, formatText } from "./report.js";
import type { ProbeConfig } from "./types.js";
import { VERSION } from "./version.js";

const HELP = `pg-tenant-probe ${VERSION}
Prove that Postgres row-level security keeps tenants apart.

Usage
  pg-tenant-probe [options]          run the probe
  pg-tenant-probe init [--supabase]  print a starter config

Options
  -c, --config <file>    config file (.json, .js, .mjs). Default: tenant-probe.config.{json,mjs,js}
      --db <url>         connection string. Default: $DATABASE_URL
      --writes           also probe UPDATE / DELETE / tenant reassignment (rolled back)
  -f, --format <fmt>     text (default) | markdown | json
      --json <file>      also write the full JSON report to <file>
      --fail-on <level>  error (default) | warn
      --no-color         plain output
  -h, --help             show this help
  -v, --version          show the version

Exit codes: 0 no errors · 1 findings at the --fail-on level · 2 usage, config or connection error.
Run it against a staging or CI database: write probes are rolled back, but triggers still fire.
`;

const DEFAULT_CONFIGS = ["tenant-probe.config.json", "tenant-probe.config.mjs", "tenant-probe.config.js"];

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function loadConfig(path: string | undefined): Promise<ProbeConfig> {
  let file = path;
  if (!file) {
    for (const candidate of DEFAULT_CONFIGS) {
      if (await exists(candidate)) {
        file = candidate;
        break;
      }
    }
  }
  if (!file) throw new ConfigError(`no config file: pass --config or create ${DEFAULT_CONFIGS[0]} (try: pg-tenant-probe init)`);
  const full = resolve(file);
  if (extname(full) === ".json") {
    try {
      return JSON.parse(await readFile(full, "utf8")) as ProbeConfig;
    } catch (error) {
      throw new ConfigError(`cannot read ${file}: ${(error as Error).message}`);
    }
  }
  const mod = (await import(pathToFileURL(full).href)) as { default?: ProbeConfig };
  if (!mod.default) throw new ConfigError(`${file} must have a default export`);
  return mod.default;
}

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      config: { type: "string", short: "c" },
      db: { type: "string" },
      writes: { type: "boolean" },
      format: { type: "string", short: "f", default: "text" },
      json: { type: "string" },
      "fail-on": { type: "string", default: "error" },
      "no-color": { type: "boolean" },
      supabase: { type: "boolean" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
    },
  });

  if (values.help) return process.stdout.write(HELP), 0;
  if (values.version) return process.stdout.write(`${VERSION}\n`), 0;
  if (positionals[0] === "init") {
    process.stdout.write(JSON.stringify(starterConfig(values.supabase ? "supabase" : "generic"), null, 2) + "\n");
    return 0;
  }
  if (positionals.length) throw new ConfigError(`unknown command "${positionals[0]}"`);

  const format = values.format;
  if (format !== "text" && format !== "markdown" && format !== "json") throw new ConfigError(`--format must be text, markdown or json`);
  const failOn = values["fail-on"];
  if (failOn !== "error" && failOn !== "warn") throw new ConfigError(`--fail-on must be error or warn`);

  const config = await loadConfig(values.config);
  if (values.writes) config.writes = true;
  normalizeConfig(config); // fail on a bad config before touching the database
  const connectionString = values.db ?? process.env.DATABASE_URL;
  if (!connectionString) throw new ConfigError("no database: pass --db or set DATABASE_URL");

  const client = new pg.Client({ connectionString, application_name: "pg-tenant-probe" });
  await client.connect();
  try {
    const report = await probe(client, config);
    const color = !values["no-color"] && !process.env.NO_COLOR && process.stdout.isTTY === true;
    if (format === "json") process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    else if (format === "markdown") process.stdout.write(formatMarkdown(report));
    else process.stdout.write(formatText(report, { color }));
    if (values.json) await writeFile(values.json, JSON.stringify(report, null, 2) + "\n");
    if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, formatMarkdown(report));
    return exitCode(report, failOn);
  } finally {
    await client.end();
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`pg-tenant-probe: ${message}\n`);
    process.exit(2);
  },
);
