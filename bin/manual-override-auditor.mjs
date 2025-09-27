#!/usr/bin/env node
import { readFile, realpath, stat, lstat, writeFile, rename, unlink } from 'node:fs/promises';
import { resolve, relative, dirname, basename, isAbsolute, sep, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { audit, incomplete, timestamp, LIMITS } from '../src/index.mjs';

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === '--help') {
  process.stdout.write('Usage: manual-override-auditor --root DIR --input FILE --as-of YYYY-MM-DDTHH:mm:ssZ [--out FILE] [--human]\nJSON report goes to stdout; --out also writes it within root. --human prints a summary to stderr.\n');
  process.exitCode = 0;
} else {
  let root, input, out, asOf, human = false;
  try {
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '--human') { human = true; continue; }
      if (!['--root', '--input', '--out', '--as-of'].includes(a) || i + 1 >= args.length) throw new Error('invalid option or missing value');
      const value = args[++i];
      if (a === '--root') { if (root) throw new Error('duplicate root'); root = value; }
      if (a === '--input') { if (input) throw new Error('duplicate input'); input = value; }
      if (a === '--out') { if (out) throw new Error('duplicate output'); out = value; }
      if (a === '--as-of') { if (asOf) throw new Error('duplicate time'); asOf = value; }
    }
    if (!root || !input || !timestamp(asOf) || isAbsolute(input) || (out && isAbsolute(out))) throw new Error('root, relative input, and valid as-of required');
    root = await realpath(root);
    if (!(await stat(root)).isDirectory()) throw new Error('root is not a directory');
  } catch { process.stderr.write('Invalid configuration. Use --help.\n'); process.exit(2); }
  const inside = path => { const rel = relative(root, path); return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel)); };
  let result, inputPath;
  try {
    inputPath = await realpath(resolve(root, input));
    if (!inside(inputPath)) throw new Error('outside root');
    const meta = await stat(inputPath);
    if (!meta.isFile()) throw new Error('not a file');
    if (meta.size > LIMITS.bytes) result = incomplete('byte-limit', 'Input exceeds 1048576 bytes.');
    else {
      const bytes = await readFile(inputPath, { signal: AbortSignal.timeout(LIMITS.milliseconds) });
      if (bytes.length > LIMITS.bytes) result = incomplete('byte-limit', 'Input exceeds 1048576 bytes.');
      else {
        let doc;
        try { doc = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
        catch { result = incomplete('input-unreadable', 'Input could not be decoded or parsed as JSON.'); }
        if (!result) result = audit(doc, asOf);
      }
    }
  } catch { result = incomplete('input-unreadable', 'Input could not be read within the declared root.'); }
  const rendered = `${JSON.stringify(result, null, 2)}\n`;
  if (out) {
    try {
      const destination = resolve(root, out);
      if (destination === resolve(root, input)) throw new Error('output aliases named input');
      const parent = await realpath(dirname(destination));
      if (!inside(parent) || !inside(destination)) throw new Error('outside root');
      let old;
      try { old = await lstat(destination); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      if (old?.isSymbolicLink() || old?.isDirectory()) throw new Error('invalid output');
      if (old && inputPath) {
        const source = await stat(inputPath);
        if (old.dev === source.dev && old.ino === source.ino) throw new Error('output aliases input');
      }
      const temp = join(parent, `.${basename(destination)}.${randomUUID()}.tmp`);
      try { await writeFile(temp, rendered, { flag: 'wx', mode: 0o600 }); await rename(temp, destination); }
      catch (e) { await unlink(temp).catch(() => {}); throw e; }
    } catch { process.stderr.write('Output destination refused or write failed.\n'); process.exit(2); }
  }
  process.stdout.write(rendered);
  if (human) process.stderr.write(`Manual overrides: ${result.status}; ${result.summary.checked} events evaluated; ${result.summary.errors} findings.\n`);
  process.exitCode = result.status === 'pass' ? 0 : result.status === 'fail' ? 1 : 2;
}
