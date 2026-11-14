// node --test .github/scripts/*.test.mjs
// The release job's fixture check and suite report (check-fixtures.mjs). The probes run against
// fake servers on 127.0.0.1, so nothing leaves the machine.
import assert from "node:assert/strict";
import net from "node:net";
import { after, describe, test } from "node:test";
import { FIXTURES, SUITES, addresses, checkFixtures, mongoHello, parseCargoLog, parseVitestLog, probe, report, tdsPrelogin, waitFor } from "./check-fixtures.mjs";

const fixture = (env) => FIXTURES.find((f) => f.env === env);
const servers = [];
after(() => servers.forEach((s) => s.close()));

/** A fake server: onConnect(socket) and onData(socket, buffer) script what it says. */
async function fakeServer({ onConnect, onData } = {}) {
  const server = net.createServer((socket) => {
    socket.on("error", () => {});
    onConnect?.(socket);
    let buf = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      onData?.(socket, buf);
    });
  });
  servers.push(server);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { host: "127.0.0.1", port: server.address().port };
}

/** A minimal OP_MSG answer to `requestId`, with `extra` bytes in its body. */
function mongoReply(requestId, extra = Buffer.alloc(0), opCode = 2013) {
  const header = Buffer.alloc(16);
  header.writeInt32LE(16 + extra.length, 0);
  header.writeInt32LE(99, 4);
  header.writeInt32LE(requestId, 8);
  header.writeInt32LE(opCode, 12);
  return Buffer.concat([header, extra]);
}

describe("addresses", () => {
  test("reads the formats the app's tests parse, never returning logins", () => {
    assert.deepEqual(addresses(fixture("SQLROG_TEST_TARGETS"), "127.0.0.1:3306:root:pw,127.0.0.1:3307:root:pw"), [
      { host: "127.0.0.1", port: 3306 },
      { host: "127.0.0.1", port: 3307 },
    ]);
    assert.deepEqual(addresses(fixture("SQLROG_MONGO_TEST_REPLSET"), "127.0.0.1:27020"), [{ host: "127.0.0.1", port: 27020 }]);
    assert.deepEqual(addresses(fixture("SQLROG_DYNAMO_TEST_ENDPOINT"), "http://127.0.0.1:18000"), [{ host: "127.0.0.1", port: 18000, url: "http://127.0.0.1:18000" }]);
  });
  test("refuses unset, empty and malformed values", () => {
    assert.throws(() => addresses(fixture("SQLROG_MSSQL_TEST_TARGETS"), undefined), /SQLROG_MSSQL_TEST_TARGETS isn't set/);
    assert.throws(() => addresses(fixture("SQLROG_MSSQL_TEST_TARGETS"), "  "), /isn't set/);
    assert.throws(() => addresses(fixture("SQLROG_MSSQL_TEST_TARGETS"), "127.0.0.1:14333"), /isn't host:port:user:password/);
    assert.throws(() => addresses(fixture("SQLROG_MSSQL_TEST_TARGETS"), "127.0.0.1:abc:sa:pw"), /no valid port/);
    assert.throws(() => addresses(fixture("SQLROG_DYNAMO_TEST_ENDPOINT"), "127.0.0.1:18000"), /isn't http:\/\/host:port/);
  });
  test("error messages never contain the password", () => {
    try {
      addresses(fixture("SQLROG_MSSQL_TEST_TARGETS"), "127.0.0.1:99999:sa:Secret!Pw");
      assert.fail("should throw");
    } catch (e) {
      assert.ok(!e.message.includes("Secret"));
    }
  });
});

describe("protocol probes", () => {
  test("MySQL: a protocol 10 greeting passes, an error packet doesn't", async () => {
    const good = await fakeServer({ onConnect: (s) => s.write(Buffer.from([0x0a, 0, 0, 0, 0x0a, 0x38])) });
    assert.equal(await probe(fixture("SQLROG_TEST_TARGETS"), good), null);
    const refused = await fakeServer({ onConnect: (s) => s.write(Buffer.from([0x10, 0, 0, 0, 0xff, 0x6a])) });
    assert.match(await probe(fixture("SQLROG_TEST_TARGETS"), refused), /error packet/);
  });

  test("PostgreSQL: the SSLRequest is answered with N or S", async () => {
    let got;
    const good = await fakeServer({ onData: (s, buf) => ((got = buf), s.write("N")) });
    assert.equal(await probe(fixture("SQLROG_PG_TEST_TARGETS"), good), null);
    assert.deepEqual([...got], [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]);
    const wrong = await fakeServer({ onData: (s) => s.write("E") });
    assert.match(await probe(fixture("SQLROG_PG_TEST_TARGETS"), wrong), /isn't a PostgreSQL/);
  });

  test("SQL Server: a well-formed PRELOGIN gets a type 4 answer", async () => {
    const packet = tdsPrelogin();
    assert.equal(packet[0], 0x12);
    assert.equal(packet.readUInt16BE(2), packet.length);
    let got;
    const good = await fakeServer({ onData: (s, buf) => ((got = buf), s.write(Buffer.from([0x04, 0x01, 0, 8, 0, 0, 1, 0]))) });
    assert.equal(await probe(fixture("SQLROG_MSSQL_TEST_TARGETS"), good), null);
    assert.deepEqual(got, packet);
    const wrong = await fakeServer({ onData: (s) => s.write(Buffer.from([0x0a, 0, 0, 0, 0, 0, 0, 0])) });
    assert.match(await probe(fixture("SQLROG_MSSQL_TEST_TARGETS"), wrong), /isn't a TDS answer/);
  });

  test("MongoDB: hello is a valid OP_MSG and the answer must be to that request", async () => {
    const hello = mongoHello(7);
    assert.equal(hello.readInt32LE(0), hello.length);
    assert.equal(hello.readInt32LE(12), 2013);
    assert.ok(hello.includes(Buffer.from("hello\0")) && hello.includes(Buffer.from("admin\0")));
    const good = await fakeServer({ onData: (s, buf) => s.write(mongoReply(buf.readInt32LE(4))) });
    assert.equal(await probe(fixture("SQLROG_MONGO_TEST_TARGETS"), good), null);
    const otherRequest = await fakeServer({ onData: (s, buf) => s.write(mongoReply(buf.readInt32LE(4) + 1)) });
    assert.match(await probe(fixture("SQLROG_MONGO_TEST_TARGETS"), otherRequest), /different request/);
    const legacy = await fakeServer({ onData: (s, buf) => s.write(mongoReply(buf.readInt32LE(4), Buffer.alloc(0), 1)) });
    assert.match(await probe(fixture("SQLROG_MONGO_TEST_TARGETS"), legacy), /isn't a MongoDB OP_MSG answer/);
  });

  test("MongoDB replica set: must be a replica set and the writable primary", async () => {
    const rs = fixture("SQLROG_MONGO_TEST_REPLSET");
    const setName = Buffer.from("\x02setName\0\x04\0\0\0rs0\0", "latin1");
    const primary = Buffer.from("\x08isWritablePrimary\0\x01", "latin1");
    const secondary = Buffer.from("\x08isWritablePrimary\0\x00", "latin1");
    const reply = (extra) => fakeServer({ onData: (s, buf) => s.write(mongoReply(buf.readInt32LE(4), extra)) });
    assert.equal(await probe(rs, await reply(Buffer.concat([primary, setName]))), null);
    assert.match(await probe(rs, await reply(primary)), /standalone server/);
    assert.match(await probe(rs, await reply(Buffer.concat([secondary, setName]))), /not \(yet\) the writable primary/);
  });

  test("a port that accepts and closes (Docker's proxy with nothing behind it) fails", async () => {
    const proxy = await fakeServer({ onConnect: (s) => s.end() });
    assert.equal(await probe(fixture("SQLROG_MONGO_TEST_TARGETS"), proxy), "the connection closed without an answer");
  });

  test("a server that never answers times out", async () => {
    const silent = await fakeServer();
    assert.equal(await probe(fixture("SQLROG_MSSQL_TEST_TARGETS"), silent, { timeoutMs: 200 }), "no answer in time");
  });

  test("nothing listening fails", async () => {
    const closed = await fakeServer();
    servers.pop().close();
    await new Promise((r) => setTimeout(r, 50));
    assert.match(await probe(fixture("SQLROG_TEST_TARGETS"), closed), /ECONNREFUSED/);
  });

  test("DynamoDB: any HTTP answer passes, no answer fails", async () => {
    const http = fixture("SQLROG_DYNAMO_TEST_ENDPOINT");
    const answering = async () => new Response("{}", { status: 400 });
    assert.equal(await probe(http, { url: "http://127.0.0.1:18000" }, { fetch: answering }), null);
    const refusing = async () => {
      throw new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } });
    };
    assert.equal(await probe(http, { url: "http://127.0.0.1:18000" }, { fetch: refusing }), "ECONNREFUSED");
  });
});

describe("waitFor", () => {
  test("retries until the check passes", async () => {
    let t = 0;
    let calls = 0;
    const r = await waitFor(async () => (++calls < 3 ? "not yet" : null), { deadlineMs: 60_000, now: () => t, sleep: async (ms) => (t += ms) });
    assert.deepEqual(r, { problem: null, seconds: 4 });
  });
  test("gives up at the deadline with the last problem", async () => {
    let t = 0;
    const r = await waitFor(async () => "still starting", { deadlineMs: 10_000, now: () => t, sleep: async (ms) => (t += ms) });
    assert.deepEqual(r, { problem: "still starting", seconds: 10 });
  });
});

describe("checkFixtures", () => {
  const env = {
    SQLROG_TEST_TARGETS: "127.0.0.1:3306:root:pw,127.0.0.1:3307:root:pw",
    SQLROG_PG_TEST_TARGETS: "127.0.0.1:5432:postgres:pw",
    SQLROG_MSSQL_TEST_TARGETS: "127.0.0.1:14333:sa:Yogurt!Test2026",
    SQLROG_MONGO_TEST_TARGETS: "127.0.0.1:27018:root:pw",
    SQLROG_MONGO_TEST_REPLSET: "127.0.0.1:27020",
    SQLROG_DYNAMO_TEST_ENDPOINT: "http://127.0.0.1:18000",
  };
  const instant = async (check) => ({ problem: await check(), seconds: 0 });

  test("passes when every fixture is set and answers, and lists what CI doesn't cover", async () => {
    const { ok, lines } = await checkFixtures(env, { probeFn: async () => null, wait: instant });
    assert.equal(ok, true);
    assert.equal(lines.filter((l) => l.startsWith("ok ")).length, 7);
    assert.ok(lines.includes("--   not in CI: MongoDB TLS (SQLROG_MONGO_TEST_TLS unset)"));
    assert.ok(!lines.join("\n").includes("Yogurt!Test2026"));
  });

  test("fails when a fixture is missing", async () => {
    const { SQLROG_MSSQL_TEST_TARGETS: _, ...partial } = env;
    const { ok, lines } = await checkFixtures(partial, { probeFn: async () => null, wait: instant });
    assert.equal(ok, false);
    assert.ok(lines.includes("FAIL SQL Server: SQLROG_MSSQL_TEST_TARGETS isn't set"));
  });

  test("fails when one server doesn't answer", async () => {
    const probeFn = async (f, a) => (a.port === 3307 ? "no answer in time" : null);
    const { ok, lines } = await checkFixtures(env, { probeFn, wait: instant });
    assert.equal(ok, false);
    assert.ok(lines.includes("FAIL MySQL/MariaDB (SQLROG_TEST_TARGETS) at 127.0.0.1:3307: no answer in time"));
  });
});

describe("the suite report", () => {
  const log = (suites) =>
    suites
      .map(([running, result]) => `     ${running}\n\nrunning 3 tests\ntest a ... ok\n\n${result ?? ""}\n`)
      .join("\n");
  const okResult = (n) => `test result: ok. ${n} passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.10s`;
  const all = [
    ["Running unittests src/lib.rs (target/debug/deps/yogurtsql_lib-1)", okResult(410)],
    ["Running unittests src/main.rs (target/debug/deps/yogurtsql-2)", okResult(0)],
    ["Running tests/integration.rs (target/debug/deps/integration-3)", okResult(60)],
    ["Running tests/integration_dynamo.rs (target/debug/deps/integration_dynamo-4)", okResult(6)],
    ["Running tests/integration_mcp.rs (target/debug/deps/integration_mcp-5)", okResult(5)],
    ["Running tests/integration_mongo.rs (target/debug/deps/integration_mongo-6)", okResult(13)],
    ["Running tests/integration_mssql.rs (target/debug/deps/integration_mssql-7)", okResult(10)],
    ["Running tests/integration_pg.rs (target/debug/deps/integration_pg-8)", okResult(38)],
    ["Running tests/integration_sqlite.rs (target/debug/deps/integration_sqlite-9)", okResult(15)],
    ["Doc-tests yogurtsql_lib", okResult(0)],
  ];
  const env = {
    SQLROG_TEST_TARGETS: "127.0.0.1:3306:root:pw,127.0.0.1:3307:root:pw",
    SQLROG_PG_TEST_TARGETS: "127.0.0.1:5432:postgres:pw",
    SQLROG_MSSQL_TEST_TARGETS: "127.0.0.1:14333:sa:pw",
    SQLROG_MONGO_TEST_TARGETS: "127.0.0.1:27018:root:pw",
    SQLROG_MONGO_TEST_REPLSET: "127.0.0.1:27020",
    SQLROG_DYNAMO_TEST_ENDPOINT: "http://127.0.0.1:18000",
  };

  test("parses every binary's counts, with ANSI colors and Windows paths", () => {
    const suites = parseCargoLog(`\x1b[32m     Running\x1b[0m tests\\integration_pg.rs (x)\n${okResult(38)}\n${log(all)}`);
    assert.deepEqual(suites[0], { name: "tests/integration_pg.rs", result: { status: "ok", passed: 38, failed: 0, ignored: 1, filtered: 0 } });
    assert.equal(suites.length, all.length + 1);
    assert.equal(suites.at(-1).name, "doc-tests yogurtsql_lib");
  });

  test("a full run passes, one line per suite with its fixtures and what it didn't exercise", () => {
    const { ok, lines } = report(parseCargoLog(log(all)), env, { vitest: "327 passed (327)" });
    assert.equal(ok, true, lines.join("\n"));
    assert.equal(lines[0], "frontend (vitest): 327 passed (327)");
    assert.ok(lines.includes("ok   tests/integration_mssql.rs: 10 passed, 0 failed, 1 ignored | fixtures: SQL Server 127.0.0.1:14333 | not exercised: SQL Server over an SSH tunnel"));
    assert.ok(lines.includes("ok   tests/integration_mongo.rs: 13 passed, 0 failed, 1 ignored | fixtures: MongoDB 127.0.0.1:27018; MongoDB replica set 127.0.0.1:27020 | not exercised: MongoDB TLS, MongoDB over an SSH tunnel"));
    assert.ok(lines.includes("ok   tests/integration_sqlite.rs: 15 passed, 0 failed, 1 ignored | fixtures: none (temporary files, no server)"));
    assert.ok(lines.includes("     doc-tests yogurtsql_lib: 0 passed, 0 failed, 1 ignored"));
    assert.ok(!lines.join("\n").includes("pw"));
  });

  test("fails when a required suite didn't run", () => {
    const { ok, lines } = report(parseCargoLog(log(all.filter(([r]) => !r.includes("integration_mssql")))), env);
    assert.equal(ok, false);
    assert.match(lines.find((l) => l.includes("integration_mssql")), /^FAIL tests\/integration_mssql\.rs: didn't run/);
  });

  test("fails when a suite ran no tests, or failed", () => {
    const zero = all.map(([r, res]) => [r, r.includes("integration_dynamo") ? okResult(0) : res]);
    assert.match(report(parseCargoLog(log(zero)), env).lines.find((l) => l.includes("integration_dynamo")), /^FAIL .*\(ran no tests\)/);
    const failed = all.map(([r, res]) => [r, r.includes("integration_pg") ? "test result: FAILED. 37 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s" : res]);
    const out = report(parseCargoLog(log(failed)), env);
    assert.equal(out.ok, false);
    assert.match(out.lines.find((l) => l.includes("integration_pg")), /^FAIL tests\/integration_pg\.rs: 37 passed, 1 failed, 0 ignored \(failed\)/);
  });

  test("fails when a suite ran without its fixture (it would have skipped itself)", () => {
    const { SQLROG_MONGO_TEST_REPLSET: _, ...partial } = env;
    const { ok, lines } = report(parseCargoLog(log(all)), partial);
    assert.equal(ok, false);
    assert.match(lines.find((l) => l.includes("integration_mongo")), /\(fixture not set: SQLROG_MONGO_TEST_REPLSET\).*MISSING SQLROG_MONGO_TEST_REPLSET/);
  });

  test("a binary that started but never printed its result didn't finish", () => {
    const cut = [...all.slice(0, 3), ["Running tests/integration_dynamo.rs (x)", null]];
    assert.match(report(parseCargoLog(log(cut)), env).lines.find((l) => l.includes("integration_dynamo")), /didn't finish/);
  });

  test("every required suite is in the list the report checks", () => {
    assert.deepEqual(SUITES.map((s) => s.name), [
      "src/lib.rs (unit)",
      "tests/integration.rs",
      "tests/integration_pg.rs",
      "tests/integration_mcp.rs",
      "tests/integration_mssql.rs",
      "tests/integration_mongo.rs",
      "tests/integration_dynamo.rs",
      "tests/integration_sqlite.rs",
    ]);
  });

  test("reads vitest's summary line", () => {
    assert.equal(parseVitestLog("\n \x1b[2m Test Files \x1b[22m 30 passed (30)\n      Tests  2 failed | 325 passed (327)\n"), "2 failed | 325 passed (327)");
    assert.equal(parseVitestLog("nothing here"), null);
  });
});
