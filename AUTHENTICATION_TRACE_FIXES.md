# Authentication Trace Pollution Fixes

## Problem

The identity vessel was producing many failed authentication traces with the following issues:

### 1. Incorrect HTTP Status Codes
The `/v1/auth/resolve` endpoint was returning HTTP 200 OK for ALL authentication attempts, even when authentication failed. This caused:
- Confusing API responses with `{ success: true, data: { authenticated: false } }`
- Improper error handling by calling services
- Violation of HTTP semantics (401/403 should be used for auth failures)

### 2. Excessive Trace Collection
Every failed authentication attempt was being traced and sent to the database due to:
- `ALWAYS_TRACE_FAILURES=true` by default
- No sampling for failed authentications
- Database pollution with traces showing `success: false, orgId: undefined, keyId: undefined`

### 3. Poor Observability
The logs showed many failed traces but no indication of:
- Why authentication was failing
- What API keys were being sent
- Whether these were legitimate failures or just health checks/monitoring

## Solutions Implemented

### Fix 1: Proper HTTP Status Codes

**File**: `src/index.ts`

Changed the `/v1/auth/resolve` endpoint to return:
- **401 Unauthorized** when authentication fails (with error details)
- **200 OK** only when authentication succeeds
- **400 Bad Request** for malformed requests

**Before**:
```typescript
const result = await resolveAuthentication(impulse);

return c.json({
  success: true,  // Always true!
  data: result
});
```

**After**:
```typescript
const result = await resolveAuthentication(impulse);

// Return proper HTTP status based on authentication result
if (!result.authenticated) {
  return c.json({
    success: false,
    error: {
      code: 'AUTHENTICATION_FAILED',
      message: result.reason || 'Authentication failed'
    }
  }, 401);
}

return c.json({
  success: true,
  data: result
});
```

### Fix 2: Updated Calling Services

**File**: `repos/deployment/vessels/metabob-activity-api/src/services/auth.ts`

Updated `validateApiKeyViaIdentityVessel` to handle the new 401 status:
- Check for 401 specifically before checking `!response.ok`
- Extract error message from 401 response
- Avoid network error fallback for definitive auth failures

### Fix 3: Reduced Trace Sampling

**File**: `repos/deployment/charts/identity-vessel/values.yaml`

Added environment variables to control trace collection:
```yaml
env:
  - name: TRACE_SAMPLE_RATE
    value: "0.01"  # Sample 1% of successful auth attempts
  - name: ALWAYS_TRACE_FAILURES
    value: "false"  # Don't trace every failed auth
```

This reduces database pollution while still collecting enough data for:
- Debugging (via logs)
- Learning patterns (via 1% sampling of successes)
- Monitoring (via metrics)

## Impact

### Before
- Every health check or unauthenticated request created a DB trace
- HTTP 200 responses for failed auth confused calling services
- Database filled with useless `success: false` traces

### After
- Failed auth returns 401 (proper HTTP semantics)
- Only 1% of successful authentications are traced (sufficient for learning)
- Failed authentications are logged but not traced (reduces DB load)
- Calling services can properly handle auth failures

## Testing

### Type Checking
```bash
cd repos/deployment/vessels/identity-vessel
bun run typecheck  # ✓ Passes
```

### Manual Testing
```bash
# Test failed authentication (should return 401)
curl -X POST http://identity.metabob.local/v1/auth/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "impulse": {
      "type": "authentication",
      "pointer": {
        "type": "apiKey",
        "apiKey": "invalid-key"
      }
    }
  }'

# Expected: HTTP 401 with error details
```

## Deployment

### Canary Deployment
```bash
# 1. Sync changes to deployment repo
cd repos/deployment
git checkout dev

# 2. Push to trigger canary deployment
git add vessels/identity-vessel/src/index.ts
git add charts/identity-vessel/values.yaml
git add vessels/metabob-activity-api/src/services/auth.ts
git commit -m "fix(identity): return 401 for failed auth, reduce trace sampling"
git push origin dev

# 3. Monitor canary deployment
kubectl get pods -n activity-system -l environment=canary
kubectl logs -n activity-system -l app.kubernetes.io/name=identity-vessel,environment=canary -f
```

### Validation
After deployment, verify:
1. Failed auth returns 401 (not 200)
2. Database trace volume decreases
3. Activity-API properly handles 401 responses

## Related Files

- `src/index.ts` - `/v1/auth/resolve` endpoint
- `src/resolvers/auth.ts` - Authentication resolution logic
- `src/services/trace.ts` - Trace collection service
- `repos/deployment/charts/identity-vessel/values.yaml` - Helm values
- `repos/deployment/vessels/metabob-activity-api/src/services/auth.ts` - Calling service

## Future Improvements

1. **Better Error Context**: Add more detail to auth failure logs (API key prefix, failure reason)
2. **Metrics**: Add Prometheus metrics for auth success/failure rates
3. **Rate Limiting**: Add rate limiting for failed auth attempts to prevent abuse
4. **Trace Filtering**: Add configuration to specify which failure types to trace (e.g., trace revoked keys, but not invalid formats)
