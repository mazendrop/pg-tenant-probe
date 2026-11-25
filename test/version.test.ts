import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";
import { VERSION } from "../src/version.js";

it("VERSION matches package.json", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  expect(VERSION).toBe(pkg.version);
});
