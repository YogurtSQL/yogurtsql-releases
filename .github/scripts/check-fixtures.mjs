// The release test job's database fixtures (build-release.yml).
//
//   node check-fixtures.mjs check
//     Fails unless every required SQLROG_* variable is set and every server it names answers in
//     its own protocol (MySQL greeting, PostgreSQL SSLRequest, SQL Server TDS pre-login, MongoDB
//     hello, DynamoDB HTTP). A bare TCP connect isn't enough: Docker's port proxy accepts
//     connections before anything listens behind it. Waits up to FIXTURE_WAIT_SECONDS (240).
//
//   node check-fixtures.mjs report <cargo test log> [<vitest log>]
//     One line per test suite: passed/failed/ignored counts, the fixtures it ran against, and the
//     configurations it didn't exercise. Fails when a required suite didn't run, ran no tests, or
//     a fixture it needs isn't set. Writes the same lines to $GITHUB_STEP_SUMMARY.
//
// The integration tests skip themselves (and pass) when their variable is missing, so these two
// checks are what makes a passing run mean the engines were really tested.
//
// Only engine names, host:port and counts are printed; never logins, passwords or test output
// (this repository's logs are public).
import { appendFileSync, readFileSync } from "node:fs";
import net from "node:net";
import { pathToFileURL } from "node:url";

/** The servers a release run must test against. */
export const FIXTURES = [
  { env: "SQLROG_TEST_TARGETS", engine: "MySQL/MariaDB", format: "targets", probe: "mysql" },
  { env: "SQLROG_PG_TEST_TARGETS", engine: "PostgreSQL", format: "targets", probe: "postgres" },
  { env: "SQLROG_MSSQL_TEST_TARGETS", engine: "SQL Server", format: "targets", probe: "tds" },
  { env: "SQLROG_MONGO_TEST_TARGETS", engine: "MongoDB", format: "targets", probe: "mongo" },
  { env: "SQLROG_MONGO_TEST_REPLSET", engine: "MongoDB replica set", format: "hostport", probe: "mongo-rs" },
  { env: "SQLROG_DYNAMO_TEST_ENDPOINT", engine: "DynamoDB Local", format: "url", probe: "http" },
];

/** Configurations the suites can test but CI doesn't provide yet: reported, not required. */
export const OPTIONAL = [
  { env: "SQLROG_TEST_TLS", what: "MySQL TLS and client certificates" },
  { env: "SQLROG_TEST_OPENSSH", what: "MySQL over an SSH tunnel" },
  { env: "SQLROG_PG_TEST_OPENSSH", what: "PostgreSQL over an SSH tunnel" },
  { env: "SQLROG_MSSQL_TEST_OPENSSH", what: "SQL Server over an SSH tunnel" },
  { env: "SQLROG_MONGO_TEST_TLS", what: "MongoDB TLS" },
  { env: "SQLROG_MONGO_TEST_OPENSSH", what: "MongoDB over an SSH tunnel" },
];

/** Every suite a release run must show, with the fixtures (required, optional) it uses. */
export const SUITES = [
  { name: "src/lib.rs (unit)", required: [], optional: [] },
  { name: "tests/integration.rs", required: ["SQLROG_TEST_TARGETS"], optional: ["SQLROG_TEST_TLS", "SQLROG_TEST_OPENSSH"] },
  { name: "tests/integration_pg.rs", required: ["SQLROG_PG_TEST_TARGETS"], optional: ["SQLROG_PG_TEST_OPENSSH"] },
  { name: "tests/integration_mcp.rs", required: ["SQLROG_TEST_TARGETS", "SQLROG_PG_TEST_TARGETS"], optional: [] },
  { name: "tests/integration_mssql.rs", required: ["SQLROG_MSSQL_TEST_TARGETS"], optional: ["SQLROG_MSSQL_TEST_OPENSSH"] },
  { name: "tests/integration_mongo.rs", required: ["SQLROG_MONGO_TEST_TARGETS", "SQLROG_MONGO_TEST_REPLSET"], optional: ["SQLROG_MONGO_TEST_TLS", "SQLROG_MONGO_TEST_OPENSSH"] },
  { name: "tests/integration_dynamo.rs", required: ["SQLROG_DYNAMO_TEST_ENDPOINT"], optional: [] },
  { name: "tests/integration_sqlite.rs", required: [], optional: [], note: "temporary files, no server" },
];

// --- the variables ------------------------------------------------------------------------------

/**
 * The host:port pairs a fixture variable names, or throws when it's empty or malformed. The
 * formats are the ones the app's tests parse: "host:port:user:pass[,...]", "host:port" and
 * "http://host:port".
 */
export function addresses(fixture, value) {
  const raw = (value ?? "").trim();
  if (!raw) throw new Error(`${fixture.env} isn't set`);
  const port = (p, what) => {
    if (!/^\d{1,5}$/.test(p ?? "") || Number(p) < 1 || Number(p) > 65535) throw new Error(`${fixture.env}: ${what} has no valid port`);
    return Number(p);
  };
  if (fixture.format === "url") {
    const m = /^http:\/\/([^/:]+):(\d+)\/?$/.exec(raw);
    if (!m) throw new Error(`${fixture.env} isn't http://host:port`);
    return [{ host: m[1], port: port(m[2], "the endpoint"), url: raw }];
  }
  const entries = fixture.format === "targets" ? raw.split(",").filter(Boolean) : [raw];
  return entries.map((entry, i) => {
    const parts = entry.split(":");
    const need = fixture.format === "targets" ? 4 : 2;
    if (parts.length < need || !parts[0]) throw new Error(`${fixture.env}: entry ${i + 1} isn't ${fixture.format === "targets" ? "host:port:user:password" : "host:port"}`);
    return { host: parts[0], port: port(parts[1], `entry ${i + 1}`) };
  });
}

// --- protocol probes ------------------------------------------------------------------------------

/** MySQL/MariaDB: the server speaks first, with a protocol 10 greeting. */
function mysqlAccept(buf) {
  if (buf.length < 5) return "more";
  if (buf[4] === 0x0a) return "ok";
  if (buf[4] === 0xff) return "it answered with an error packet instead of a greeting";
  return `it isn't a MySQL greeting (first byte 0x${buf[4].toString(16)})`;
}

/** PostgreSQL: SSLRequest, answered with one byte, S or N. */
const PG_SSL_REQUEST = Buffer.from([0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]);
function postgresAccept(buf) {
  if (buf.length < 1) return "more";
  return buf[0] === 0x53 || buf[0] === 0x4e ? "ok" : `it isn't a PostgreSQL SSLRequest answer (0x${buf[0].toString(16)})`;
}

/** SQL Server: a TDS PRELOGIN packet (VERSION and ENCRYPTION options), answered with a type 4 packet. */
export function tdsPrelogin() {
  const options = Buffer.from([
    0x00, 0x00, 0x0b, 0x00, 0x06, // VERSION at offset 11, 6 bytes
    0x01, 0x00, 0x11, 0x00, 0x01, // ENCRYPTION at offset 17, 1 byte
    0xff, // terminator
    0, 0, 0, 0, 0, 0, // version
    0x02, // ENCRYPT_NOT_SUP
  ]);
  const header = Buffer.from([0x12, 0x01, 0, 0, 0, 0, 0x01, 0x00]);
  header.writeUInt16BE(header.length + options.length, 2);
  return Buffer.concat([header, options]);
}
function tdsAccept(buf) {
  if (buf.length < 8) return "more";
  return buf[0] === 0x04 ? "ok" : `it isn't a TDS answer (packet type 0x${buf[0].toString(16)})`;
}

/** MongoDB: OP_MSG { hello: 1, $db: "admin" }, answered with an OP_MSG to the same request. */
export function mongoHello(requestId) {
  const el = (type, name, value) => Buffer.concat([Buffer.from([type]), Buffer.from(`${name}\0`), value]);
  const int32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeInt32LE(n);
    return b;
  };
  const str = (s) => Buffer.concat([int32(Buffer.byteLength(s) + 1), Buffer.from(`${s}\0`)]);
  const elements = Buffer.concat([el(0x10, "hello", int32(1)), el(0x02, "$db", str("admin"))]);
  const doc = Buffer.concat([int32(4 + elements.length + 1), elements, Buffer.from([0])]);
  const body = Buffer.concat([int32(0), Buffer.from([0]), doc]); // flagBits, section kind 0
  const header = Buffer.concat([int32(16 + body.length), int32(requestId), int32(0), int32(2013)]);
  return Buffer.concat([header, body]);
}
// In hello's answer: "setName" (a string) and isWritablePrimary: true (BSON boolean 0x08, value 1).
const SET_NAME = Buffer.from("\x02setName\0", "latin1");
const WRITABLE_PRIMARY = Buffer.from("\x08isWritablePrimary\0\x01", "latin1");
function mongoAccept(requestId, { replicaSet = false } = {}) {
  return (buf) => {
    if (buf.length < 16) return "more";
    if (buf.readInt32LE(12) !== 2013) return `it isn't a MongoDB OP_MSG answer (opCode ${buf.readInt32LE(12)})`;
    if (buf.readInt32LE(8) !== requestId) return "it answered a different request";
    if (!replicaSet) return "ok";
    if (buf.length < buf.readInt32LE(0)) return "more";
    if (!buf.includes(SET_NAME)) return "it's a standalone server, not a replica set";
    if (!buf.includes(WRITABLE_PRIMARY)) return "it's a replica set member but not (yet) the writable primary";
    return "ok";
  };
}

/**
 * Connects, sends `send` (if any) and feeds what comes back to accept(buffer), which says "ok",
 * "more" or what's wrong. Resolves to null when it answered correctly, or the problem.
 */
export function probeTcp({ host, port }, { send, accept, timeoutMs = 5000 }) {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    let done = false;
    const socket = net.connect({ host, port });
    const finish = (problem) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(problem);
    };
    const timer = setTimeout(() => finish("no answer in time"), timeoutMs);
    socket.on("connect", () => {
      if (send) socket.write(send);
    });
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const verdict = accept(buf);
      if (verdict !== "more") finish(verdict === "ok" ? null : verdict);
    });
    socket.on("error", (e) => finish(e.code ?? e.message));
    socket.on("close", () => finish("the connection closed without an answer"));
  });
}

/** Any HTTP answer from the endpoint (DynamoDB Local answers 400 to an unsigned GET). */
export async function probeHttp({ url }, { timeoutMs = 5000, fetch = globalThis.fetch } = {}) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    await res.arrayBuffer().catch(() => {});
    return null;
  } catch (e) {
    return e?.cause?.code ?? e?.cause?.errors?.[0]?.code ?? (e?.cause?.message || e?.message || String(e));
  }
}

let nextRequestId = 1;
/** Probes one address of a fixture: null when it answered in its protocol, else the problem. */
export function probe(fixture, address, options = {}) {
  switch (fixture.probe) {
    case "mysql":
      return probeTcp(address, { accept: mysqlAccept, ...options });
    case "postgres":
      return probeTcp(address, { send: PG_SSL_REQUEST, accept: postgresAccept, ...options });
    case "tds":
      return probeTcp(address, { send: tdsPrelogin(), accept: tdsAccept, ...options });
    case "mongo":
    case "mongo-rs": {
      const id = nextRequestId++;
      return probeTcp(address, { send: mongoHello(id), accept: mongoAccept(id, { replicaSet: fixture.probe === "mongo-rs" }), ...options });
    }
    case "http":
      return probeHttp(address, options);
    default:
      return Promise.resolve(`unknown probe ${fixture.probe}`);
  }
}

/** Retries probe() until it succeeds or the deadline passes. Resolves to { problem, seconds }. */
export async function waitFor(check, { deadlineMs, intervalMs = 2000, now = Date.now, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  const start = now();
  for (;;) {
    const problem = await check();
    if (!problem || now() - start >= deadlineMs) return { problem, seconds: Math.round((now() - start) / 1000) };
    await sleep(intervalMs);
  }
}

/** The check command: every required fixture is set and answers. Returns the lines and whether all passed. */
export async function checkFixtures(env, { deadlineMs = 240_000, probeFn = probe, wait = waitFor } = {}) {
  const lines = [];
  let ok = true;
  for (const fixture of FIXTURES) {
    let list;
    try {
      list = addresses(fixture, env[fixture.env]);
    } catch (e) {
      lines.push(`FAIL ${fixture.engine}: ${e.message}`);
      ok = false;
      continue;
    }
    for (const address of list) {
      const where = `${address.host}:${address.port}`;
      const { problem, seconds } = await wait(() => probeFn(fixture, address), { deadlineMs });
      if (problem) {
        ok = false;
        lines.push(`FAIL ${fixture.engine} (${fixture.env}) at ${where}: ${problem}`);
      } else {
        lines.push(`ok   ${fixture.engine} (${fixture.env}) at ${where} answers${seconds ? ` (after ${seconds}s)` : ""}`);
      }
    }
  }
  for (const o of OPTIONAL) if (!env[o.env]) lines.push(`--   not in CI: ${o.what} (${o.env} unset)`);
  return { ok, lines };
}

// --- the report -------------------------------------------------------------------------------------

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");

/** Each test binary in a `cargo test` log, with its counts, in the order cargo ran them. */
export function parseCargoLog(text) {
  const suites = [];
  let current = null;
  for (const raw of stripAnsi(text).split(/\r?\n/)) {
    const line = raw.trim();
    let m;
    if ((m = /^Running (unittests )?(\S+)/.exec(line))) {
      const file = m[2].replaceAll("\\", "/");
      current = { name: m[1] ? `${file} (unit)` : file, result: null };
      suites.push(current);
    } else if ((m = /^Doc-tests (\S+)/.exec(line))) {
      current = { name: `doc-tests ${m[1]}`, result: null };
      suites.push(current);
    } else if (current && (m = /^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out/.exec(line))) {
      current.result = { status: m[1], passed: Number(m[2]), failed: Number(m[3]), ignored: Number(m[4]), filtered: Number(m[6]) };
      current = null;
    }
  }
  return suites;
}

/** vitest's "Tests  2 failed | 325 passed (327)" line, or null. */
export function parseVitestLog(text) {
  const line = stripAnsi(text).split(/\r?\n/).map((l) => l.trim()).find((l) => /^Tests\s+.*\(\d+\)$/.test(l));
  return line ? line.replace(/^Tests\s+/, "").replace(/\s+/g, " ") : null;
}

function fixtureText(envName, env) {
  const fixture = FIXTURES.find((f) => f.env === envName);
  try {
    return `${fixture.engine} ${addresses(fixture, env[envName]).map((a) => `${a.host}:${a.port}`).join(", ")}`;
  } catch {
    return null;
  }
}

/** The report command's lines, and whether the run counts. */
export function report(suites, env, { vitest } = {}) {
  const lines = [];
  let ok = true;
  if (vitest !== undefined) lines.push(`frontend (vitest): ${vitest ?? "no summary line found"}`);
  for (const expected of SUITES) {
    const ran = suites.find((s) => s.name === expected.name);
    const fixtures = expected.required.map((e) => fixtureText(e, env) ?? `MISSING ${e}`);
    const missing = expected.required.filter((e) => !fixtureText(e, env));
    const notExercised = expected.optional.filter((e) => !env[e]).map((e) => OPTIONAL.find((o) => o.env === e).what);
    const where = [fixtures.length ? `fixtures: ${fixtures.join("; ")}` : expected.note ? `fixtures: none (${expected.note})` : null, notExercised.length ? `not exercised: ${notExercised.join(", ")}` : null].filter(Boolean);
    if (!ran?.result) {
      ok = false;
      lines.push(`FAIL ${expected.name}: ${ran ? "didn't finish" : "didn't run"}${where.length ? ` | ${where.join(" | ")}` : ""}`);
      continue;
    }
    const r = ran.result;
    const problems = [];
    if (r.status !== "ok") problems.push("failed");
    if (r.passed + r.failed === 0) problems.push("ran no tests");
    if (missing.length) problems.push(`fixture not set: ${missing.join(", ")}`);
    if (problems.length) ok = false;
    lines.push(`${problems.length ? "FAIL" : "ok  "} ${expected.name}: ${r.passed} passed, ${r.failed} failed, ${r.ignored} ignored${problems.length ? ` (${problems.join("; ")})` : ""}${where.length ? ` | ${where.join(" | ")}` : ""}`);
  }
  for (const s of suites) {
    if (!SUITES.some((e) => e.name === s.name) && s.result) lines.push(`     ${s.name}: ${s.result.passed} passed, ${s.result.failed} failed, ${s.result.ignored} ignored`);
  }
  return { ok, lines };
}

// --- CLI ----------------------------------------------------------------------------------------------

function summary(title, lines) {
  if (!process.env.GITHUB_STEP_SUMMARY) return;
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### ${title}\n\n${lines.map((l) => `- \`${l}\``).join("\n")}\n\n`);
}

async function main(argv) {
  const [command, ...rest] = argv;
  if (command === "check") {
    const seconds = Number(process.env.FIXTURE_WAIT_SECONDS ?? 240);
    const { ok, lines } = await checkFixtures(process.env, { deadlineMs: seconds * 1000 });
    console.log(lines.join("\n"));
    summary("Test fixtures", lines);
    if (!ok) console.log("::error::A required test fixture is missing or doesn't answer, so the engine tests would skip themselves. Not running the tests.");
    return ok ? 0 : 1;
  }
  if (command === "report" && rest[0]) {
    let cargo = "";
    try {
      cargo = readFileSync(rest[0], "utf8");
    } catch {
      console.log(`::error::No cargo test log at ${rest[0]}.`);
    }
    let vitest;
    if (rest[1]) {
      try {
        vitest = parseVitestLog(readFileSync(rest[1], "utf8"));
      } catch {
        vitest = null;
      }
    }
    const { ok, lines } = report(parseCargoLog(cargo), process.env, { vitest });
    console.log(lines.join("\n"));
    summary("Test suites", lines);
    if (!ok) console.log("::error::A required test suite didn't run, ran nothing, failed, or ran without its fixture.");
    return ok ? 0 : 1;
  }
  console.error("usage: node check-fixtures.mjs check | report <cargo test log> [<vitest log>]");
  return 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
