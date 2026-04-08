/**
 * MiniBob instance authentication service - DEPRECATED
 *
 * This file is deprecated as of 2026-04-08.
 * Migration 052 removed the minibob_record ACCESS method from SurrealDB.
 * MiniBob instances now use standard API key authentication.
 *
 * This file is retained for reference but is no longer called by any endpoints.
 * The /v1/auth/minibob/signin and /v2/auth/minibob/signin endpoints return 410 Gone.
 */

import { Surreal } from 'surrealdb';
import { config } from './config';
import type { MiniBobAuthResult } from '../types';

/**
 * Authenticate MiniBob instance using RECORD access - DEPRECATED
 *
 * @deprecated This function is no longer used. Migration 052 removed the minibob_record ACCESS method.
 * Use standard API key authentication instead.
 *
 * Returns JWT token and organization/project context
 */
export async function authenticateMiniBobInstance(
  instance_id: string,
  api_key: string
): Promise<MiniBobAuthResult> {
  // Create a fresh SurrealDB connection for RECORD auth
  // Note: We cannot use the connection pool here because RECORD auth
  // changes the connection's authentication context
  const db = new Surreal();

  try {
    await db.connect(config.surrealdb.url);
    await db.use({
      namespace: config.surrealdb.namespace,
      database: config.surrealdb.database
    });

    // Authenticate using RECORD access (same as activity-api)
    // This verifies API key hash and returns a SurrealDB JWT token
    const authResult = await db.signin({
      access: 'minibob_record',
      variables: {
        instance_id,
        api_key,
      },
    });

    // SurrealDB SDK v2+ returns token as string or { access: "JWT..." }
    const jwtToken = typeof authResult === 'string'
      ? authResult
      : (authResult as { access: string }).access;

    // Query $auth to get org_id and project_id from authenticated session
    const authQuery = await db.query<[{
      org_id: string;
      project_id?: string;
    }]>(
      `RETURN {
        org_id: $auth.org_id,
        project_id: $auth.project_id
      }`
    );
    const instance = authQuery[0] || {};

    return {
      token: jwtToken,
      org_id: instance.org_id,
      project_id: instance.project_id,
    };
  } finally {
    // Always close the connection
    await db.close();
  }
}

/**
 * Common error handler for MiniBob authentication - DEPRECATED
 *
 * @deprecated This function is no longer used. Endpoints return 410 Gone.
 */
export function handleAuthError(error: unknown): { statusCode: number; message: string } {
  const errorMessage = error instanceof Error ? error.message : String(error);

  // Handle auth-specific errors
  if (
    errorMessage.includes('No access method found') ||
    errorMessage.includes('credentials were invalid') ||
    errorMessage.includes('Invalid credentials')
  ) {
    return {
      statusCode: 401,
      message: 'Invalid instance credentials'
    };
  }

  return {
    statusCode: 500,
    message: errorMessage
  };
}
