#!/usr/bin/env bun
/**
 * Bootstrap API Key Generator
 *
 * Generates the first admin API key for identity-vessel.
 * This key is used to generate all other keys via the API.
 *
 * Usage:
 *   bun run scripts/generate-bootstrap-key.ts
 *
 * Environment Variables:
 *   API_KEY_SECRET - HMAC signing secret (required)
 *   NODE_ENV - Environment (development/production)
 *   BOOTSTRAP_ORG_ID - Organization ID (default: metabob_com)
 *   BOOTSTRAP_USER_ID - User ID (default: usr_admin)
 *
 * Output:
 *   - Prints the bootstrap admin key (save this securely!)
 *   - Writes key metadata to .bootstrap-key.json (for reference, not the key itself)
 */

import { existsSync, writeFileSync } from 'fs'
import { join } from 'path'

// Import key generation from the service
import { generateApiKey, type ApiKeyResult } from '../src/services/keyGeneration'

// Configuration
const API_KEY_SECRET = process.env.API_KEY_SECRET
const NODE_ENV = process.env.NODE_ENV || 'development'
const BOOTSTRAP_ORG_ID = process.env.BOOTSTRAP_ORG_ID || 'metabob_com'
const BOOTSTRAP_USER_ID = process.env.BOOTSTRAP_USER_ID || 'usr_admin'
const METADATA_FILE = join(process.cwd(), '.bootstrap-key.json')

// Validate environment
if (!API_KEY_SECRET) {
  console.error('❌ Error: API_KEY_SECRET environment variable is required')
  console.error('')
  console.error('Set it with:')
  console.error('  export API_KEY_SECRET="your-secret-key-min-32-chars"')
  console.error('')
  process.exit(1)
}

if (API_KEY_SECRET.length < 32) {
  console.error('❌ Error: API_KEY_SECRET must be at least 32 characters')
  process.exit(1)
}

console.log('=== Bootstrap API Key Generator ===')
console.log('')
console.log('Configuration:')
console.log(`  Environment: ${NODE_ENV}`)
console.log(`  Organization: ${BOOTSTRAP_ORG_ID}`)
console.log(`  User: ${BOOTSTRAP_USER_ID}`)
console.log(`  Secret Length: ${API_KEY_SECRET.length} chars`)
console.log('')

// Check if bootstrap key already exists
if (existsSync(METADATA_FILE)) {
  console.log('⚠️  Warning: Bootstrap key metadata file already exists')
  console.log(`    Location: ${METADATA_FILE}`)
  console.log('')

  const existing = JSON.parse(await Bun.file(METADATA_FILE).text())
  console.log('Existing bootstrap key:')
  console.log(`  Key ID: ${existing.keyId}`)
  console.log(`  Created: ${existing.createdAt}`)
  console.log(`  Prefix: ${existing.prefix}`)
  console.log('')

  // Ask if user wants to continue
  const shouldContinue = await new Promise<boolean>((resolve) => {
    process.stdout.write('Generate a new bootstrap key? (y/N): ')
    process.stdin.once('data', (data) => {
      const answer = data.toString().trim().toLowerCase()
      resolve(answer === 'y' || answer === 'yes')
    })
  })

  if (!shouldContinue) {
    console.log('Aborted. Use existing bootstrap key.')
    process.exit(0)
  }

  console.log('')
}

// Generate bootstrap admin key
console.log('Generating bootstrap admin key...')

const bootstrapKey: ApiKeyResult = generateApiKey(
  BOOTSTRAP_ORG_ID,
  BOOTSTRAP_USER_ID,
  {
    scopes: ['read', 'write', 'admin'],
    expiresInDays: 3650, // 10 years for bootstrap key
  }
)

console.log('✓ Bootstrap key generated')
console.log('')

// Save metadata (NOT the key itself)
const metadata = {
  keyId: bootstrapKey.keyId,
  prefix: bootstrapKey.prefix,
  orgId: BOOTSTRAP_ORG_ID,
  userId: BOOTSTRAP_USER_ID,
  scopes: ['read', 'write', 'admin'],
  environment: NODE_ENV,
  createdAt: new Date().toISOString(),
  expiresAt: bootstrapKey.expiresAt,
  note: 'Bootstrap admin key - DO NOT DELETE'
}

writeFileSync(METADATA_FILE, JSON.stringify(metadata, null, 2))

console.log('✓ Metadata saved to:', METADATA_FILE)
console.log('')

console.warn('⚠️  SECURITY REMINDER: Do NOT commit .bootstrap-key.json to git.')
console.warn('   It is listed in .gitignore, but verify with: git status .bootstrap-key.json')
console.warn('   Store the key ID and secret only in environment variables or K8s secrets:')
console.warn('     kubectl create secret generic identity-bootstrap-key \\')
console.warn('       --from-literal=key-id=<keyId> \\')
console.warn('       --from-literal=api-key=<key> \\')
console.warn('       -n activity-system')
console.warn('')

// Display the key (ONLY TIME IT'S SHOWN!)
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
console.log('🔑 BOOTSTRAP ADMIN API KEY (save this securely!):')
console.log('')
console.log(bootstrapKey.key)
console.log('')
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
console.log('')
console.log('⚠️  WARNING: This key will NOT be shown again!')
console.log('   Save it to a secure location NOW.')
console.log('')
console.log('Key Details:')
console.log(`  Key ID: ${bootstrapKey.keyId}`)
console.log(`  Prefix: ${bootstrapKey.prefix}`)
console.log(`  Scopes: read, write, admin`)
console.log(`  Expires: ${bootstrapKey.expiresAt}`)
console.log('')

// Usage instructions
console.log('Usage:')
console.log('')
console.log('1. Save the key to your environment:')
console.log('')
console.log('   # For local development')
console.log(`   echo "ADMIN_API_KEY=${bootstrapKey.key}" >> .env`)
console.log('')
console.log('   # For Kubernetes deployment')
console.log(`   kubectl create secret generic identity-vessel-admin-key \\`)
console.log(`     --from-literal=admin-api-key=${bootstrapKey.key} \\`)
console.log(`     -n activity-system`)
console.log('')
console.log('2. Use the key to generate other API keys:')
console.log('')
console.log(`   curl -X POST http://identity.metabob.local/v1/keys/generate \\`)
console.log(`     -H "Authorization: Bearer ${bootstrapKey.key}" \\`)
console.log(`     -H "Content-Type: application/json" \\`)
console.log(`     -d '{`)
console.log(`       "targetUserId": "usr_test",`)
console.log(`       "name": "Test User Key",`)
console.log(`       "scopes": ["read", "write"]`)
console.log(`     }'`)
console.log('')
console.log('3. Test the key:')
console.log('')
console.log(`   curl -X POST http://identity.metabob.local/v1/auth/resolve \\`)
console.log(`     -H "Content-Type: application/json" \\`)
console.log(`     -d '{`)
console.log(`       "impulse": {`)
console.log(`         "type": "authentication",`)
console.log(`         "pointer": {`)
console.log(`           "type": "apiKey",`)
console.log(`           "apiKey": "${bootstrapKey.key}"`)
console.log(`         }`)
console.log(`       }`)
console.log(`     }'`)
console.log('')

// Exit with success
process.exit(0)
