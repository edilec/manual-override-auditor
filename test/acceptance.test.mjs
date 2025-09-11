import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink, link, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

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
  const d = structuredClone(clean); d.overrides[0].originalResult = 'allow';
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
