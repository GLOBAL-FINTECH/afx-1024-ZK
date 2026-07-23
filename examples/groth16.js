import { randomField, buildAuthorizationInput, proveGroth16, verifyGroth16 } from '../src/index.js';
const input = buildAuthorizationInput({ secret: randomField(), salt: randomField(), message: 'transfer 25 SBQ', domain: 'sibaq:1990' });
const bundle = await proveGroth16({ circuit: 'authorization', input });
console.log(await verifyGroth16(bundle));
