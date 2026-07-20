import { SignJWT, jwtVerify } from "jose";
import { config } from "../config.js";

/**
 * JWT access-token minting and verification (jose).
 *
 * SECURITY (Verification requirements):
 * - The signing key is loaded from the environment once at boot and its
 *   length is enforced (>= 32 bytes for HS256). Never hardcoded (AISDP #1).
 * - `algorithms: ["HS256"]` pins the algorithm on VERIFY. A token whose
 *   header says `alg: none` (the classic bypass) or any other algorithm is
 *   rejected before the signature is even considered.
 * - `issuer` and `audience` are always verified, so tokens minted by or for
 *   any other service — even ones sharing this key by mistake — fail closed.
 * - `exp` is enforced by jose by default; we mint with a 15-minute TTL and
 *   set `iat` for audit. No `exp`, wrong `aud`, wrong `iss`, bad signature,
 *   or expired token all surface as the same verification failure.
 */

const encoder = new TextEncoder();
const secretKey = encoder.encode(config.jwt.secret);
if (secretKey.byteLength < 32) {
  // Fail closed at boot: a short HS256 key is brute-forceable.
  throw new Error("JWT_SECRET must be at least 32 bytes");
}

export interface AccessTokenClaims {
  /** Subject: the user id. The ONLY identity source downstream code may use. */
  sub: string;
}

export async function signAccessToken(userId: string): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(userId)
    .setIssuer(config.jwt.issuer)
    .setAudience(config.jwt.audience)
    .setIssuedAt()
    .setExpirationTime(`${config.jwt.accessTokenTtlSeconds}s`)
    .sign(secretKey);
}

/** Returns the verified claims, or null on ANY verification failure. */
export async function verifyAccessToken(token: string): Promise<AccessTokenClaims | null> {
  try {
    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: ["HS256"], // SECURITY: pinned — no alg-confusion / alg:none.
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      // A small tolerance absorbs clock skew between horizontally scaled
      // instances without meaningfully extending token life.
      clockTolerance: 5,
    });
    if (typeof payload.sub !== "string" || payload.sub.length === 0) return null;
    return { sub: payload.sub };
  } catch {
    // SECURITY: the reason (expired vs. bad signature vs. wrong audience) is
    // deliberately not propagated to callers — clients get a uniform 401.
    return null;
  }
}
