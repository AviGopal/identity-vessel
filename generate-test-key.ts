import { generateApiKey } from './src/services/keyGeneration.js';

const result = generateApiKey(
  'org_test', 
  'user_test',
  { 
    name: 'MiniBob Test Key',
    scopes: ['read', 'write']
  }
);

console.log(JSON.stringify({
  key: result.key,
  keyId: result.keyId,
  secret: process.env.API_KEY_SECRET || 'dev-secret-change-in-production'
}, null, 2));
