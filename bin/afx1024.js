#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { buildAuthorizationInput, buildSecretKnowledgeInput, proveGroth16, verifyGroth16, proofDigest, randomField } from '../src/index.js';

const [cmd, ...args] = process.argv.slice(2);
const flags = parse(args);
try {
  if (cmd === 'secret') {
    console.log(JSON.stringify({ secret: randomField().toString(), salt: randomField().toString() }, null, 2));
  } else if (cmd === 'prove-knowledge') {
    const input = buildSecretKnowledgeInput({ secret: need('secret'), salt: need('salt'), scope: flags.scope ?? '0' });
    await output(await proveGroth16({ circuit: 'secret-knowledge', input, artifactsDir: flags.artifacts }), flags.out);
  } else if (cmd === 'prove-auth') {
    const input = buildAuthorizationInput({ secret: need('secret'), salt: need('salt'), message: need('message'), domain: need('domain'), nonce: flags.nonce });
    await output(await proveGroth16({ circuit: 'authorization', input, artifactsDir: flags.artifacts }), flags.out);
  } else if (cmd === 'verify') {
    const bundle = JSON.parse(await readFile(need('proof'), 'utf8'));
    console.log(JSON.stringify({ ...(await verifyGroth16(bundle, { artifactsDir: flags.artifacts })), digest: proofDigest(bundle) }, null, 2));
  } else {
    console.log('Usage: afx1024 secret | prove-knowledge --secret N --salt N [--scope N] | prove-auth --secret N --salt N --message TEXT --domain TEXT [--nonce N] | verify --proof FILE');
  }
} catch (e) { console.error(JSON.stringify({ ok:false, code:e.code ?? 'ERROR', error:e.message }, null, 2)); process.exitCode=1; }
function parse(xs){const o={};for(let i=0;i<xs.length;i++){if(xs[i].startsWith('--'))o[xs[i].slice(2)]=xs[i+1]&&!xs[i+1].startsWith('--')?xs[++i]:true;}return o;}
function need(k){if(flags[k]===undefined)throw new Error(`Missing --${k}`);return flags[k];}
async function output(v,file){const s=JSON.stringify(v,null,2);if(file)await writeFile(file,s+'\n');else console.log(s);}
