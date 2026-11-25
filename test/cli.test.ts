import { execFile, execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { promisify } from "node:util";
import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";
import { afterAll, beforeAll, expect, it } from "vitest";
import type { Report } from "../src/types.js";

// End to end: build the package, serve the fixture over the real Postgres wire
// protocol (PGlite behind a socket), and run the CLI with the `pg` driver.
const run = promisify(execFile);
const root = new URL("..", import.meta.url).pathname;
let db: PGlite;
let server: PGLiteSocketServer;
let url: string;

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
  });
}

async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run(process.execPath, ["dist/cli.js", ...args], { cwd: root, env: { ...process.env, NO_COLOR: "1", GITHUB_STEP_SUMMARY: "" } });
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code: number; stdout: string; stderr: string };
    return { code: err.code, stdout: err.stdout, stderr: err.stderr };
  }
}

beforeAll(async () => {
  execFileSync("npx", ["tsc", "-p", "tsconfig.build.json"], { cwd: root, stdio: "inherit" });
  db = new PGlite();
  await db.exec(await readFile(new URL("./fixture.sql", import.meta.url), "utf8"));
  const port = await freePort();
  server = new PGLiteSocketServer({ db, port, host: "127.0.0.1" });
  await server.start();
  url = `postgres://postgres@127.0.0.1:${port}/postgres?sslmode=disable`;
});
afterAll(async () => {
  await server?.stop();
  await db?.close();
});

it("prints help and version", async () => {
  expect((await cli(["--help"])).stdout).toContain("Usage");
  expect((await cli(["--version"])).stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
});

it("prints a starter config", async () => {
  const { stdout, code } = await cli(["init", "--supabase"]);
  expect(code).toBe(0);
  expect(JSON.parse(stdout)).toMatchObject({ preset: "supabase" });
});

it("exits 2 on a bad config", async () => {
  const { code, stderr } = await cli(["--config", "package.json", "--db", "postgres://x@127.0.0.1:1/x"]);
  expect(code).toBe(2);
  expect(stderr).toContain("principals");
});

it("probes over the wire, prints the report and exits 1 on findings", async () => {
  const { code, stdout } = await cli(["--config", "examples/fixture.config.json", "--db", url, "--writes", "--format", "json"]);
  expect(code).toBe(1);
  const report = JSON.parse(stdout) as Report;
  expect(report.summary).toMatchObject({ leaks: 25, ok: false });

  const text = await cli(["--config", "examples/fixture.config.json", "--db", url]);
  expect(text.code).toBe(1);
  expect(text.stdout).toContain("CROSS_TENANT_READ");
  expect(text.stdout).toContain("Result: FAIL");
});
