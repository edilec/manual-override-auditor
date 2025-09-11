const TOOL = 'manual-override-auditor';
const SEVERITY = Object.freeze({ 'input-unreadable': 'error', 'input-invalid': 'error', 'byte-limit': 'error', 'record-limit': 'error', 'depth-limit': 'error', 'time-limit': 'error', 'no-overrides': 'error', 'decision-invalid': 'error', 'decision-duplicate': 'error', 'decision-unknown': 'error', 'override-invalid': 'error', 'override-duplicate': 'error', 'actor-missing': 'error', 'reason-missing': 'error', 'scope-missing': 'error', 'follow-up-missing': 'error', 'original-result-mismatch': 'error', 'override-no-change': 'error', 'override-before-decision': 'error', 'override-in-future': 'error', 'expiry-invalid': 'error', 'override-expired': 'error' });
const INCOMPLETE = new Set(['input-unreadable', 'input-invalid', 'byte-limit', 'record-limit', 'depth-limit', 'time-limit', 'decision-invalid', 'decision-duplicate', 'decision-unknown', 'override-in-future']);
export const LIMITS = Object.freeze({ bytes: 1_048_576, records: 1000, depth: 16, milliseconds: 5000 });
const cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const record = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const usable = x => typeof x === 'string' && x.replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\p{Cf}]/gu, '').trim().length > 0;
const result = x => x === 'allow' || x === 'deny';
export const timestamp = x => typeof x === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(x) && !Number.isNaN(Date.parse(x)) && new Date(x).toISOString().replace('.000Z', 'Z') === x;
function tooDeep(x, depth = 0) {
  if (depth > LIMITS.depth) return true;
  if (!x || typeof x !== 'object') return false;
  return Object.values(x).some(v => tooDeep(v, depth + 1));
}
function add(findings, ruleId, pointer, message) {
  if (!(ruleId in SEVERITY)) throw new Error('unknown rule');
  findings.push({ ruleId, severity: SEVERITY[ruleId], message, location: { file: '@input', pointer } });
}
function report(findings, checked) {
  findings.sort((a, b) => cmp(a.location.file, b.location.file) || cmp(a.location.pointer ?? '', b.location.pointer ?? '') || cmp(a.ruleId, b.ruleId));
  const status = findings.some(f => INCOMPLETE.has(f.ruleId)) ? 'incomplete' : findings.some(f => f.severity === 'error') ? 'fail' : 'pass';
  return { schemaVersion: '1', tool: TOOL, status, summary: { checked, errors: findings.filter(f => f.severity === 'error').length, warnings: 0 }, findings };
}
export function incomplete(ruleId, message) { const findings = []; add(findings, ruleId, '', message); return report(findings, 0); }
export function audit(doc, asOf, now = () => performance.now()) {
  const started = now(), findings = [];
  if (!record(doc) || doc.schemaVersion !== '1' || !Array.isArray(doc.decisions) || !Array.isArray(doc.overrides)) {
    add(findings, 'input-invalid', '', 'Expected a version 1 document with decisions and overrides arrays.'); return report(findings, 0);
  }
  if (tooDeep(doc)) { add(findings, 'depth-limit', '', 'Document exceeds nesting depth 16.'); return report(findings, 0); }
  if (doc.decisions.length > LIMITS.records || doc.overrides.length > LIMITS.records) {
    add(findings, 'record-limit', '', 'Decisions or overrides exceed 1000 records.'); return report(findings, 0);
  }
  if (!doc.overrides.length) { add(findings, 'no-overrides', '/overrides', 'At least one override is required.'); return report(findings, 0); }
  const decisions = new Map(), ambiguous = new Set();
  for (const [i, d] of doc.decisions.entries()) {
    if (now() - started > LIMITS.milliseconds) { add(findings, 'time-limit', '', 'Processing exceeded 5000 milliseconds.'); return report(findings, 0); }
    if (!record(d) || !usable(d.id) || !result(d.result) || !timestamp(d.recordedAt)) {
      add(findings, 'decision-invalid', `/decisions/${i}`, 'Decision lacks a usable identifier, result, or timestamp.'); continue;
    }
    if (decisions.has(d.id)) { ambiguous.add(d.id); add(findings, 'decision-duplicate', `/decisions/${i}`, 'Decision identifier is duplicated.'); }
    else decisions.set(d.id, d);
  }
  const overrideIds = new Set(); let checked = 0;
  for (const [i, o] of doc.overrides.entries()) {
    if (now() - started > LIMITS.milliseconds) { add(findings, 'time-limit', '', 'Processing exceeded 5000 milliseconds.'); break; }
    const at = `/overrides/${i}`;
    if (!record(o) || !usable(o.id) || !usable(o.decisionId) || !result(o.originalResult) || !result(o.overrideResult) || !timestamp(o.occurredAt) || !timestamp(o.expiresAt)) {
      add(findings, 'override-invalid', at, 'Override lacks a usable identifier, result, or timestamp.'); continue;
    }
    checked++;
    if (overrideIds.has(o.id)) add(findings, 'override-duplicate', `${at}/id`, 'Override identifier is duplicated.');
    else overrideIds.add(o.id);
    if (!usable(o.actor)) add(findings, 'actor-missing', `${at}/actor`, 'Override actor is missing.');
    if (!usable(o.reason)) add(findings, 'reason-missing', `${at}/reason`, 'Override reason is missing.');
    if (!usable(o.scope)) add(findings, 'scope-missing', `${at}/scope`, 'Override scope is missing.');
    if (!usable(o.followUpEvidence)) add(findings, 'follow-up-missing', `${at}/followUpEvidence`, 'Follow-up evidence reference is missing.');
    const decision = decisions.get(o.decisionId);
    if (!decision || ambiguous.has(o.decisionId)) add(findings, 'decision-unknown', `${at}/decisionId`, 'Referenced original decision is unavailable or ambiguous.');
    else {
      if (o.originalResult !== decision.result) add(findings, 'original-result-mismatch', `${at}/originalResult`, 'Override copy differs from the recorded original result.');
      if (o.occurredAt < decision.recordedAt) add(findings, 'override-before-decision', `${at}/occurredAt`, 'Override predates the recorded original decision.');
    }
    if (o.originalResult === o.overrideResult) add(findings, 'override-no-change', `${at}/overrideResult`, 'Override result must differ from original result.');
    if (o.occurredAt > asOf) add(findings, 'override-in-future', `${at}/occurredAt`, 'Override event is later than the assessment time.');
    if (o.expiresAt <= o.occurredAt) add(findings, 'expiry-invalid', `${at}/expiresAt`, 'Expiry must follow the override event.');
    else if (o.expiresAt <= asOf) add(findings, 'override-expired', `${at}/expiresAt`, 'Override has expired at the supplied assessment time.');
  }
  return report(findings, checked);
}
