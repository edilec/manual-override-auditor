import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink, link, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { audit } from '../src/index.mjs';

const cli = new URL('../bin/manual-override-auditor.mjs', import.meta.url).pathname;
const asOf = '2026-01-02T00:00:00Z';
const clean = { schemaVersion: '1', decisions: [{ id: 'decision-a', result: 'deny', recordedAt: '2026-01-01T00:00:00Z' }], overrides: [{ id: 'override-a', decisionId: 'decision-a', originalResult: 'deny', overrideResult: 'allow', actor: 'operator', reason: 'Documented exception', scope: 'sample-operation', occurredAt: '2026-01-01T12:00:00Z', expiresAt: '2026-01-03T00:00:00Z', followUpEvidence: 'ticket-1' }] };
async function run(doc = clean, extra = []) {
  const root = await mkdtemp(join(tmpdir(), 'override-test-'));
  await writeFile(join(root, 'input.json'), typeof doc === 'string' ? doc : JSON.stringify(doc));
  const p = spawnSync(process.execPath, [cli, '--root', root, '--input', 'input.json', '--as-of', asOf, ...extra], { encoding: 'utf8', maxBuffer: 4_194_304 });
  await rm(root, { recursive: true, force: true });
  return { code: p.status, stdout: p.stdout, stderr: p.stderr, report: p.stdout ? JSON.parse(p.stdout) : null };
}
test('valid linked override passes without publishing private fields', async () => {
  const r = await run();
  assert.equal(r.code, 0); assert.equal(r.report.status, 'pass');
  assert.equal(r.report.summary.checked, 1); assert.deepEqual(r.report.findings, []);
  assert.equal(r.stdout.includes('operator'), false);
});
test('expired override fails on its own', async () => {
  const d = structuredClone(clean); d.overrides[0].expiresAt = asOf;
  const r = await run(d);
  assert.equal(r.code, 1); assert.equal(r.report.status, 'fail');
  assert.equal(r.report.findings[0].ruleId, 'override-expired');
  assert.equal(r.report.findings[0].location.pointer, '/overrides/0/expiresAt');
});
test('reasonless override fails even when all other fields are good', async () => {
  const d = structuredClone(clean); d.overrides[0].reason = '  ';
  const r = await run(d);
  assert.equal(r.code, 1); assert.equal(r.report.findings[0].ruleId, 'reason-missing');
});
test('override cannot rewrite recorded original decision', async () => {
  const d = structuredClone(clean); d.overrides[0].originalResult = 'allow'; d.overrides[0].overrideResult = 'deny';
  const r = await run(d);
  assert.equal(r.code, 1); assert.equal(r.report.status, 'fail');
  assert.equal(r.report.findings[0].ruleId, 'original-result-mismatch');
  assert.equal(r.report.findings[0].location.pointer, '/overrides/0/originalResult');
});
test('unknown decision is incomplete rather than accepted', async () => {
  const d = structuredClone(clean); d.overrides[0].decisionId = 'missing';
  const r = await run(d);
  assert.equal(r.code, 2); assert.equal(r.report.status, 'incomplete');
  assert.equal(r.report.findings[0].ruleId, 'decision-unknown');
});
test('future override is incomplete at the assessment time', async () => {
  const d = structuredClone(clean); d.overrides[0].occurredAt = '2026-01-02T12:00:00Z';
  const r = await run(d);
  assert.equal(r.code, 2); assert.equal(r.report.status, 'incomplete');
  assert.equal(r.report.findings[0].ruleId, 'override-in-future');
});
test('empty override export is incomplete, not an evaluated failure', async () => {
  const d = structuredClone(clean); d.overrides = [];
  const r = await run(d);
  assert.equal(r.code, 2); assert.equal(r.report.status, 'incomplete');
  assert.equal(r.report.findings[0].ruleId, 'no-overrides');
});
test('unusable override record is incomplete', async () => {
  const d = structuredClone(clean); d.overrides[0].expiresAt = 'bad-date';
  const r = await run(d);
  assert.equal(r.code, 2); assert.equal(r.report.status, 'incomplete');
  assert.equal(r.report.findings[0].ruleId, 'override-invalid');
});
test('duplicate override identity is incomplete', async () => {
  const d = structuredClone(clean); d.overrides.push({ ...d.overrides[0] });
  const r = await run(d);
  assert.equal(r.code, 2); assert.equal(r.report.status, 'incomplete');
  assert.equal(r.report.findings[0].ruleId, 'override-duplicate');
});
test('malformed input is incomplete and never echoes quoted payload', async () => {
  const r = await run('at position 1');
  assert.equal(r.code, 2); assert.equal(r.report.status, 'incomplete');
  assert.equal(r.stdout.includes('at position 1'), false);
});
test('input symlink escaping root is refused', async () => {
  const root = await mkdtemp(join(tmpdir(), 'override-root-'));
  const out = await mkdtemp(join(tmpdir(), 'override-out-'));
  await writeFile(join(out, 'secret.json'), 'secret-value');
  await symlink(join(out, 'secret.json'), join(root, 'input.json'));
  const p = spawnSync(process.execPath, [cli, '--root', root, '--input', 'input.json', '--as-of', asOf], { encoding: 'utf8' });
  assert.equal(p.status, 2); assert.equal(JSON.parse(p.stdout).status, 'incomplete');
  assert.equal(p.stdout.includes('secret-value'), false);
  await rm(root, { recursive: true, force: true }); await rm(out, { recursive: true, force: true });
});
test('exact override record bound is accepted and next is incomplete', async () => {
  const d = structuredClone(clean); d.overrides = Array.from({ length: 1000 }, (_, i) => ({ ...clean.overrides[0], id: String(i) }));
  const good = await run(d); assert.equal(good.code, 0); assert.equal(good.report.summary.checked, 1000);
  d.overrides.push({ ...clean.overrides[0], id: 'extra' });
  const bad = await run(d); assert.equal(bad.code, 2); assert.equal(bad.report.findings[0].ruleId, 'record-limit');
});
test('a stripped-only actor and missing follow-up fail without leaking content', async () => {
  const d = structuredClone(clean); d.overrides[0].actor = '\u0085\u202e'; d.overrides[0].followUpEvidence = '';
  const r = await run(d);
  assert.equal(r.code, 1); assert.equal(r.report.status, 'fail');
  assert.deepEqual(r.report.findings.map(f => f.ruleId), ['actor-missing', 'follow-up-missing']);
  assert.equal(r.stdout.includes('\u202e'), false);
});
test('strict UTF-8 decoding refuses invalid bytes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'override-utf8-'));
  await writeFile(join(root, 'input.json'), Buffer.from([0xff]));
  const p = spawnSync(process.execPath, [cli, '--root', root, '--input', 'input.json', '--as-of', asOf], { encoding: 'utf8' });
  assert.equal(p.status, 2); assert.equal(JSON.parse(p.stdout).findings[0].ruleId, 'input-unreadable');
  await rm(root, { recursive: true, force: true });
});
test('hard-linked output is refused without altering input', async () => {
  const root = await mkdtemp(join(tmpdir(), 'override-output-'));
  const original = JSON.stringify(clean);
  await writeFile(join(root, 'input.json'), original);
  await link(join(root, 'input.json'), join(root, 'report.json'));
  const p = spawnSync(process.execPath, [cli, '--root', root, '--input', 'input.json', '--as-of', asOf, '--out', 'report.json'], { encoding: 'utf8' });
  assert.equal(p.status, 2); assert.equal(p.stdout, '');
  assert.equal(await readFile(join(root, 'input.json'), 'utf8'), original);
  await rm(root, { recursive: true, force: true });
});
test('identical export and assessment time produce identical bytes', async () => {
  const a = await run(), b = await run();
  assert.equal(a.stdout, b.stdout);
});
test('byte bound accepts exactly 1048576 and rejects the next byte', async () => {
  const base = JSON.stringify(clean);
  const exact = base + ' '.repeat(1_048_576 - Buffer.byteLength(base));
  const at = await run(exact), over = await run(exact + ' ');
  assert.equal(at.code, 0); assert.equal(at.report.status, 'pass');
  assert.equal(over.code, 2); assert.equal(over.report.findings[0].ruleId, 'byte-limit');
});
test('depth bound accepts level 16 and rejects level 17', async () => {
  const nested = count => { const d = structuredClone(clean); let node = d; for (let i = 0; i < count; i++) { node.extra = {}; node = node.extra; } return d; };
  const at = await run(nested(16)), over = await run(nested(17));
  assert.equal(at.code, 0); assert.equal(at.report.status, 'pass');
  assert.equal(over.code, 2); assert.equal(over.report.findings[0].ruleId, 'depth-limit');
});
test('injected time bound accepts 5000 ms and rejects 5001 ms', () => {
  const clock = values => { let i = 0; return () => values[i++] ?? values.at(-1); };
  assert.equal(audit(clean, asOf, clock([0, 5000, 5000])).status, 'pass');
  const over = audit(clean, asOf, clock([0, 5001]));
  assert.equal(over.status, 'incomplete'); assert.equal(over.findings[0].ruleId, 'time-limit');
});
test('output refuses a symlink destination and preserves outside sentinel', async () => {
  const root = await mkdtemp(join(tmpdir(), 'override-out-root-')), outside = await mkdtemp(join(tmpdir(), 'override-outside-'));
  await writeFile(join(root, 'input.json'), JSON.stringify(clean));
  await writeFile(join(outside, 'sentinel.json'), 'sentinel');
  await symlink(join(outside, 'sentinel.json'), join(root, 'report.json'));
  try {
    const p = spawnSync(process.execPath, [cli, '--root', root, '--input', 'input.json', '--as-of', asOf, '--out', 'report.json'], { encoding: 'utf8' });
    assert.equal(p.status, 2); assert.equal(p.stdout, '');
    assert.equal(await readFile(join(outside, 'sentinel.json'), 'utf8'), 'sentinel');
  } finally { await rm(root, { recursive: true, force: true }); await rm(outside, { recursive: true, force: true }); }
});
test('output refuses a symlinked parent escape and preserves outside sentinel', async () => {
  const root = await mkdtemp(join(tmpdir(), 'override-parent-root-')), outside = await mkdtemp(join(tmpdir(), 'override-parent-outside-'));
  await writeFile(join(root, 'input.json'), JSON.stringify(clean));
  await writeFile(join(outside, 'report.json'), 'sentinel');
  await symlink(outside, join(root, 'linked'));
  try {
    const p = spawnSync(process.execPath, [cli, '--root', root, '--input', 'input.json', '--as-of', asOf, '--out', 'linked/report.json'], { encoding: 'utf8' });
    assert.equal(p.status, 2); assert.equal(p.stdout, '');
    assert.equal(await readFile(join(outside, 'report.json'), 'utf8'), 'sentinel');
  } finally { await rm(root, { recursive: true, force: true }); await rm(outside, { recursive: true, force: true }); }
});
test('ordinary new report output contains exactly stdout', async () => {
  const root = await mkdtemp(join(tmpdir(), 'override-allowed-'));
  const original = JSON.stringify(clean);
  await writeFile(join(root, 'input.json'), original);
  const p = spawnSync(process.execPath, [cli, '--root', root, '--input', 'input.json', '--as-of', asOf, '--out', 'report.json'], { encoding: 'utf8' });
  assert.equal(p.status, 0); assert.equal(JSON.parse(p.stdout).status, 'pass');
  assert.equal(await readFile(join(root, 'report.json'), 'utf8'), p.stdout);
  assert.equal(await readFile(join(root, 'input.json'), 'utf8'), original);
  await rm(root, { recursive: true, force: true });
});
