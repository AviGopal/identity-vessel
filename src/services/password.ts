/**
 * Password Service - Single source of truth for password operations
 *
 * Provides:
 * - Secure password hashing with Argon2id (via Bun)
 * - Password verification
 * - Password strength validation
 *
 * All other vessels should delegate to identity-vessel for password operations.
 */

/**
 * Hash a password using Argon2id
 *
 * Argon2id is the recommended password hashing algorithm that:
 * - Resists GPU attacks (memory-hard)
 * - Resists side-channel attacks (hybrid approach)
 * - Is the winner of the Password Hashing Competition
 *
 * @param password - Plain text password
 * @returns Hashed password string
 */
export async function hashPassword(password: string): Promise<string> {
  // Bun has built-in Argon2id support via Bun.password
  return await Bun.password.hash(password, {
    algorithm: 'argon2id',
    memoryCost: 65536, // 64 MB
    timeCost: 3,       // 3 iterations
  });
}

/**
 * Verify a password against a hash
 *
 * @param password - Plain text password to verify
 * @param hash - Stored password hash
 * @returns True if password matches hash
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await Bun.password.verify(password, hash);
  } catch {
    // Invalid hash format or other error
    return false;
  }
}

/**
 * Password strength validation result
 */
export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
  score: number; // 0-4 (0=weak, 4=strong)
}

/**
 * Validate password strength
 *
 * Requirements:
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one digit
 * - Optionally: special character for higher score
 *
 * @param password - Password to validate
 * @returns Validation result with score
 */
export function validatePassword(password: string): PasswordValidationResult {
  const errors: string[] = [];
  let score = 0;

  // Length check
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  } else {
    score++;
    if (password.length >= 12) score++;
  }

  // Uppercase check
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  } else {
    score++;
  }

  // Lowercase check
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  // Digit check
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one digit');
  } else {
    score++;
  }

  // Special character bonus (not required, but increases score)
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    score++;
  }

  // Cap score at 4
  score = Math.min(score, 4);

  return {
    valid: errors.length === 0,
    errors,
    score,
  };
}
