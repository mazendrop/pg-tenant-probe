/** Quote an SQL identifier: my"table -> "my""table". */
export function ident(name: string): string {
  if (name.length === 0) throw new Error("empty SQL identifier");
  if (name.includes("\u0000")) throw new Error("SQL identifier contains a NUL byte");
  return `"${name.replaceAll('"', '""')}"`;
}

/** "schema"."name" */
export function qualified(schema: string, name: string): string {
  return `${ident(schema)}.${ident(name)}`;
}

/** Is `expr` just a (possibly quoted) column name of the relation? Returns the column or null. */
export function plainColumn(expr: string, columns: readonly string[]): string | null {
  const trimmed = expr.trim();
  const quoted = /^"((?:[^"]|"")+)"$/.exec(trimmed);
  if (quoted) {
    const name = quoted[1]!.replaceAll('""', '"');
    return columns.includes(name) ? name : null;
  }
  if (/^[a-z_][a-z0-9_$]*$/.test(trimmed) && columns.includes(trimmed)) return trimmed;
  return null;
}

/** Does `name` match a pattern where a trailing "*" means "any suffix"? */
export function matchesPattern(name: string, pattern: string): boolean {
  return pattern.endsWith("*") ? name.startsWith(pattern.slice(0, -1)) : name === pattern;
}

/** Postgres error code of a driver error (pg and PGlite both expose `.code`). */
export function errorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : undefined;
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** SQLSTATE 42501: insufficient_privilege (also raised for RLS WITH CHECK violations). */
export const INSUFFICIENT_PRIVILEGE = "42501";
