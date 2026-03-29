# Authentication Trace Schema

## Principle: Authentication IS an Activity

Authentication resolution is modeled as an activity template in the learning system:

```typescript
{
  template_id: "auth_resolve_v1",
  category: "infrastructure",
  name: "Resolve Authentication Impulse",
  description: "Validate API key and return authentication context"
}
```

Every authentication request is an **execution** of this template.

---

## Why Authentication Traces are Indistinguishable

### 1. Same Schema

Authentication traces use the **exact same schema** as other activity execution traces:

```typescript
interface ExecutionTrace {
  template_id: string;      // "auth_resolve_v1"
  execution_id: string;     // "auth_1743433544986_abc123"
  status: "success" | "failed";
  start_time: string;       // ISO 8601
  end_time: string;         // ISO 8601
  duration_ms: number;      // Measured execution time
  org_id: string;
  user_id: string;
  metadata: Record<string, any>;  // Activity-specific data
}
```

### 2. Same Endpoint

Both send to `/v2/activities/execution-traces`:

```typescript
// Authentication trace (identity-vessel)
await fetch(`${ACTIVITY_API}/v2/activities/execution-traces`, {
  method: 'POST',
  body: JSON.stringify({
    template_id: "auth_resolve_v1",
    execution_id: "auth_1743433544986_abc123",
    status: "success",
    start_time: "2026-03-29T14:45:44.986Z",
    end_time: "2026-03-29T14:45:44.992Z",
    duration_ms: 6,
    org_id: "metabob_com",
    user_id: "usr_avi",
    metadata: {
      key_id: "key_abc123",
      signature_valid: true,
      revoked: false
    }
  })
});

// Regular activity trace (minibob)
await fetch(`${ACTIVITY_API}/v2/activities/execution-traces`, {
  method: 'POST',
  body: JSON.stringify({
    template_id: "fix_typescript_error_v3",
    execution_id: "exec_1743433600123_xyz789",
    status: "success",
    start_time: "2026-03-29T14:50:00.123Z",
    end_time: "2026-03-29T14:50:45.678Z",
    duration_ms: 45555,
    org_id: "metabob_com",
    user_id: "usr_avi",
    metadata: {
      error_type: "TS2345",
      files_modified: ["src/index.ts"],
      tools_used: ["edit", "bash"]
    }
  })
});
```

### 3. Same Learning Patterns

The activity-api treats both identically:

```typescript
// SurrealDB storage (same table)
CREATE activity_execution_trace CONTENT {
  template_id: $template_id,      // Could be ANY activity
  execution_id: $execution_id,
  status: $status,
  duration_ms: $duration_ms,
  // ... same fields for all traces
}

// Thompson Sampling (same algorithm)
SELECT template_id,
       count() as total,
       count_if(status = 'success') as successes,
       avg(duration_ms) as avg_duration
FROM activity_execution_trace
WHERE template_id IN $candidate_templates
GROUP BY template_id
```

---

## Key Differences (Metadata Only)

The only difference is in the **metadata** field, which is activity-specific:

### Authentication Activity Metadata

```json
{
  "metadata": {
    "activity_type": "authentication_resolution",
    "key_id": "key_abc123",
    "signature_valid": true,
    "revoked": false,
    "cached": false
  }
}
```

### Code Fix Activity Metadata

```json
{
  "metadata": {
    "activity_type": "code_fix",
    "error_type": "TS2345",
    "files_modified": ["src/index.ts"],
    "tools_used": ["edit", "bash"],
    "token_count": 1234
  }
}
```

### Test Runner Activity Metadata

```json
{
  "metadata": {
    "activity_type": "test_execution",
    "test_framework": "bun:test",
    "tests_run": 25,
    "tests_passed": 24,
    "tests_failed": 1
  }
}
```

---

## Why This Matters for Learning

### 1. Unified Analytics

The dashboard shows all activities together:

```
Template Performance (Last 24h)
┌────────────────────────────┬───────┬─────────┬──────────────┐
│ Template                   │ Count │ Success │ Avg Duration │
├────────────────────────────┼───────┼─────────┼──────────────┤
│ auth_resolve_v1            │ 15420 │  99.8%  │      1.8ms   │
│ fix_typescript_error_v3    │    45 │  91.1%  │  45555ms     │
│ run_bun_tests_v2           │    12 │ 100.0%  │  12345ms     │
│ generate_api_key_v1        │     3 │ 100.0%  │    456ms     │
└────────────────────────────┴───────┴─────────┴──────────────┘
```

### 2. Thompson Sampling Works

When selecting which activity to run, Thompson Sampling considers ALL templates:

```typescript
// metabob-activity-api/src/services/thompson-sampling.ts
export function selectTemplate(candidates: string[]): string {
  // Could include both "auth_resolve_v1" and "fix_typescript_error_v3"
  const performances = await getTemplatePerformances(candidates);

  // Sample from beta distribution based on success rates
  const samples = performances.map(p => {
    const alpha = p.successes + 1;
    const beta = p.failures + 1;
    return betaSample(alpha, beta);
  });

  // Return highest-scoring template
  return candidates[argmax(samples)];
}
```

**Note:** Authentication is so fast and deterministic that it wouldn't compete with code activities in Thompson Sampling. But the **data structure is the same**.

### 3. Ribosome Pattern

If we wanted to extract authentication into a reusable template (already is!), it works the same way:

```typescript
// Extract successful execution into template
const template = assembleTemplateFromExecution({
  template_id: "auth_resolve_v1",
  execution_id: "auth_1743433544986_abc123",
  tasks: [
    {
      id: "validate_format",
      description: "Parse and validate API key format",
      prompt: { template: "Decode base64 and verify structure" },
      validation: { requiredOutputs: ["valid_format"] }
    },
    {
      id: "verify_signature",
      description: "Verify HMAC signature with constant-time comparison",
      prompt: { template: "Compare signatures using timingSafeEqual" },
      validation: { requiredOutputs: ["signature_valid"] }
    },
    {
      id: "check_revocation",
      description: "Query Redis for revocation status",
      prompt: { template: "GET revoked:{keyId} from Redis" },
      validation: { requiredOutputs: ["not_revoked"] }
    }
  ]
});
```

---

## The Vessel Pattern

Vessels (like identity-vessel) **are** activity executors - just specialized ones:

### MiniBob (General-Purpose Vessel)

```typescript
// Executes various activities
await executeActivity({
  template_id: "fix_typescript_error_v3",
  context: { errorFile, errorMessage },
  tools: [edit, bash, read],
  llm: claude
});
```

### Identity Vessel (Specialized Vessel)

```typescript
// Executes authentication activities
await executeActivity({
  template_id: "auth_resolve_v1",
  context: { apiKey },
  tools: [hmac, redis],
  llm: none  // Deterministic, no LLM needed
});
```

**Both send the same trace format to activity-api.**

---

## Complete Flow Diagram

```
┌─────────────────┐
│ Any Vessel      │
│ (MiniBob,       │
│  Identity,      │
│  CodeReview)    │
└────────┬────────┘
         │
         │ Execute Activity
         ▼
┌─────────────────────────────────┐
│ Activity Execution              │
│ - Start timer                   │
│ - Run tasks (LLM or deterministic)
│ - Capture state transitions     │
│ - Stop timer                    │
└────────┬────────────────────────┘
         │
         │ Send Trace
         ▼
┌─────────────────────────────────┐
│ POST /v2/activities/            │
│      execution-traces           │
│                                 │
│ {                               │
│   template_id: "...",           │
│   execution_id: "...",          │
│   status: "success",            │
│   duration_ms: 123,             │
│   org_id: "...",                │
│   metadata: {...}               │
│ }                               │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ metabob-activity-api            │
│                                 │
│ INSERT INTO                     │
│   activity_execution_trace      │
│                                 │
│ UPDATE                          │
│   activity_template             │
│ SET                             │
│   success_count += 1,           │
│   avg_duration = ...,           │
│   last_executed = now()         │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Learning System                 │
│                                 │
│ - Thompson Sampling             │
│ - Pattern Recognition           │
│ - Ribosome Extraction           │
│ - Performance Analytics         │
└─────────────────────────────────┘
```

---

## Example: Authentication Activity Template

This is what gets stored in SurrealDB:

```surql
CREATE activity_template:auth_resolve_v1 CONTENT {
  id: "auth_resolve_v1",
  name: "Resolve Authentication Impulse",
  category: "infrastructure",
  description: "Validate API key with HMAC signature and return auth context",

  public: true,  -- Available to all orgs

  tasks: [
    {
      id: "decode_key",
      description: "Decode base64url-encoded API key",
      tools: ["buffer_decode"],
      llm_required: false
    },
    {
      id: "verify_signature",
      description: "Verify HMAC-SHA256 signature",
      tools: ["hmac_verify"],
      llm_required: false
    },
    {
      id: "check_revocation",
      description: "Query Redis revocation cache",
      tools: ["redis_get"],
      llm_required: false
    }
  ],

  performance_metrics: {
    total_executions: 15420,
    successful_executions: 15392,
    failed_executions: 28,
    success_rate: 0.998,
    avg_duration_ms: 1.8,
    p95_duration_ms: 3.2,
    p99_duration_ms: 5.1
  },

  created_at: time::now(),
  last_executed: time::now(),
  version: 1
};
```

---

## Benefits of Unified Schema

### 1. Simpler Architecture

One endpoint, one schema, one storage table, one learning system.

### 2. Easier Analytics

Query all activities together:

```sql
-- Slowest activities across ALL types
SELECT template_id, avg(duration_ms) as avg_duration
FROM activity_execution_trace
WHERE org_id = 'metabob_com'
  AND start_time > time::now() - 24h
GROUP BY template_id
ORDER BY avg_duration DESC
LIMIT 10;

-- Most unreliable activities
SELECT template_id,
       count_if(status = 'failed') / count() as failure_rate
FROM activity_execution_trace
WHERE org_id = 'metabob_com'
GROUP BY template_id
HAVING failure_rate > 0.05
ORDER BY failure_rate DESC;
```

### 3. Consistent Learning

Thompson Sampling, pattern recognition, and ribosome extraction work on ALL activities using the same algorithms.

### 4. Vessel Interoperability

Any vessel can execute any activity. MiniBob could execute `auth_resolve_v1` if needed. Identity vessel could execute `fix_typescript_error_v3` if it had the tools.

---

## What Makes Authentication Unique?

While the **trace format** is identical, authentication has unique characteristics:

### 1. Extreme Speed

```
auth_resolve_v1:      ~2ms
run_bun_tests_v2:     ~12s
fix_typescript_error: ~45s
```

### 2. No LLM

```
auth_resolve_v1:      deterministic (HMAC + Redis)
fix_typescript_error: LLM-based reasoning
```

### 3. High Volume

```
auth_resolve_v1:      ~15k/day (every API request)
fix_typescript_error: ~50/day (development work)
```

### 4. No State Mutation

```
auth_resolve_v1:      reads only (key validation)
fix_typescript_error: writes (modifies source code)
```

**But the trace format remains identical.**

---

## Summary

**Authentication traces ARE activity traces.**

They:
- Use the same schema
- Go to the same endpoint
- Get stored in the same table
- Participate in the same learning system

The only difference is in the `metadata` field, which contains authentication-specific details like `key_id` and `signature_valid`.

This unified approach means:
- **Simpler architecture** (one trace system for everything)
- **Easier analytics** (query all activities together)
- **Consistent learning** (same algorithms for all templates)
- **Vessel interoperability** (any vessel can execute any activity)

Authentication is just a very fast, deterministic, stateless activity - but it's still an activity.
