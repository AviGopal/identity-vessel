/**
 * Trace collection for authentication operations
 * Sends execution metrics to metabob-activity-api for learning
 */

const ACTIVITY_API_ENDPOINT = process.env.ACTIVITY_API_ENDPOINT || 'http://metabob-activity-api.activity-system.svc.cluster.local:8080';

// Sampling configuration - only send a percentage of traces
const TRACE_SAMPLE_RATE = parseFloat(process.env.TRACE_SAMPLE_RATE || '0.01'); // 1% by default
// Default behavior: true if env var is not set to literal 'false'
// Helm deployment sets this to 'false' to reduce DB load from failed auth attempts
const ALWAYS_TRACE_FAILURES = process.env.ALWAYS_TRACE_FAILURES !== 'false';

/**
 * Decide if we should sample this trace
 */
function shouldSample(success: boolean): boolean {
  // Always trace failures for debugging
  if (!success && ALWAYS_TRACE_FAILURES) {
    return true;
  }

  // Sample successful requests based on rate
  return Math.random() < TRACE_SAMPLE_RATE;
}

export interface AuthenticationTrace {
  activityType: 'authentication_resolution';
  startTime: number;
  endTime: number;
  durationMs: number;
  success: boolean;
  orgId?: string;
  userId?: string;
  keyId?: string;
  error?: string;
  metadata?: {
    cached?: boolean;
    revoked?: boolean;
    signatureValid?: boolean;
  };
}

/**
 * Send authentication trace to activity-api for learning
 */
export async function sendAuthenticationTrace(trace: AuthenticationTrace): Promise<void> {
  // Apply sampling - only send a percentage of traces
  if (!shouldSample(trace.success)) {
    return;
  }

  try {
    const response = await fetch(`${ACTIVITY_API_ENDPOINT}/v2/activities/execution-traces`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        template_id: 'auth_resolve_v1',
        execution_id: `auth_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
        status: trace.success ? 'success' : 'failed',
        start_time: new Date(trace.startTime).toISOString(),
        end_time: new Date(trace.endTime).toISOString(),
        duration_ms: trace.durationMs,
        org_id: trace.orgId || 'unknown',
        user_id: trace.userId || 'unknown',
        metadata: {
          activity_type: trace.activityType,
          key_id: trace.keyId,
          error: trace.error,
          ...trace.metadata
        }
      })
    });

    if (!response.ok) {
      console.error('[Trace] Failed to send authentication trace:', await response.text());
    } else {
      console.log('[Trace] Authentication trace sent:', {
        durationMs: trace.durationMs,
        success: trace.success,
        orgId: trace.orgId,
        keyId: trace.keyId
      });
    }
  } catch (error) {
    // Fail silently - don't let trace collection break authentication
    console.error('[Trace] Error sending trace:', error);
  }
}

/**
 * Create a trace wrapper for authentication operations
 */
export function traceAuthentication<T>(
  operation: () => Promise<T>,
  metadata?: Partial<AuthenticationTrace>
): Promise<T> {
  const startTime = Date.now();

  return operation()
    .then((result: any) => {
      const endTime = Date.now();

      // Fire-and-forget: Send trace asynchronously without blocking
      sendAuthenticationTrace({
        activityType: 'authentication_resolution',
        startTime,
        endTime,
        durationMs: endTime - startTime,
        success: result.authenticated !== false,
        orgId: result.orgId,
        userId: result.userId,
        keyId: result.keyId,
        metadata: {
          signatureValid: result.authenticated,
          ...metadata?.metadata
        }
      }).catch(err => {
        // Silently log trace errors - never fail authentication due to trace issues
        console.error('[Trace] Failed to send trace (non-blocking):', err.message);
      });

      return result;
    })
    .catch((error) => {
      const endTime = Date.now();

      // Fire-and-forget: Send failure trace asynchronously
      sendAuthenticationTrace({
        activityType: 'authentication_resolution',
        startTime,
        endTime,
        durationMs: endTime - startTime,
        success: false,
        error: error.message,
        ...metadata
      }).catch(() => {
        // Ignore trace errors
      });

      throw error;
    });
}
