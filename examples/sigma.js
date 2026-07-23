import { generateKeyPair, proveSigma, verifySigma } from '../src/index.js';
const keys = generateKeyPair();
const proof = proveSigma('authorize block 42', keys.privateKey, { context: 'afx:demo' });
console.log(verifySigma('authorize block 42', proof, { context: 'afx:demo' }));
