import {
  randomBytes,
  scrypt as scryptCb,
  timingSafeEqual,
  type ScryptOptions,
} from "node:crypto";

function scrypt(
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(password, salt, keylen, options, (err, derived) =>
      err ? reject(err) : resolve(derived),
    );
  });
}

/**
 * Password hashing with Node's built-in scrypt (memory-hard KDF).
 *
 * SECURITY (Credential Storage, OWASP A02/A07):
 * - Per-password random 16-byte salt: identical passwords produce different
 *   hashes, and rainbow tables are useless.
 * - scrypt N=2^15, r=8, p=1 (~32 MB memory per guess) makes offline
 *   cracking of a leaked table expensive. Parameters are stored inside the
 *   hash string so they can be raised later without invalidating old hashes.
 * - Verification uses timingSafeEqual — no early-exit byte comparison.
 * - Passwords are hashed immediately and never logged or stored raw.
 */

const SCRYPT_N = 2 ** 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 64;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const derived = (await scrypt(password, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 128 * 1024 * 1024,
  })) as Buffer;
  return [
    "scrypt",
    String(SCRYPT_N),
    String(SCRYPT_R),
    String(SCRYPT_P),
    salt.toString("base64"),
    derived.toString("base64"),
  ].join("$");
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, nStr, rStr, pStr, saltB64, hashB64] = parts;
  const salt = Buffer.from(saltB64 as string, "base64");
  const expected = Buffer.from(hashB64 as string, "base64");
  const derived = (await scrypt(password, salt, expected.length, {
    N: Number.parseInt(nStr as string, 10),
    r: Number.parseInt(rStr as string, 10),
    p: Number.parseInt(pStr as string, 10),
    maxmem: 128 * 1024 * 1024,
  })) as Buffer;
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

/**
 * SECURITY (user enumeration): when a login names an unknown email, we still
 * burn a real scrypt verification against this throwaway hash so the
 * response time is indistinguishable from a wrong-password attempt.
 */
export const DUMMY_HASH_PROMISE: Promise<string> = hashPassword(
  randomBytes(16).toString("hex"),
);
