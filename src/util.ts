import crypto from 'crypto';
import { Buffer } from "buffer";

const HKDF_SALT = Buffer.from('ciphercast-salt-v0.1.1', 'utf-8');
const HKDF_INFO = Buffer.from('ciphercast-aes-256-gcm-key-v0.1.1', 'utf-8');

/**
 * Derives a 32-byte AES key from an ECDH shared secret using HKDF-SHA256.
 * Replaces the old raw-SHA256 approach, which had no domain separation.
 */
export function deriveAesKeyFromSecret(secret: Buffer): Buffer {
    return Buffer.from(
        crypto.hkdfSync('sha256', secret, HKDF_SALT, HKDF_INFO, 32)
    );
}

export interface EncryptResult {
    iv: Buffer;
    tag: Buffer;
    ciphertext: Buffer;
}

export function aesGcmEncrypt(aesKey: Buffer, plaintext: Buffer): EncryptResult {
    const iv = crypto.randomBytes(12); // 96-bit IV — GCM standard
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag(); // 128-bit auth tag
    return { iv, tag, ciphertext };
}

export function aesGcmDecrypt(
    aesKey: Buffer,
    iv: Buffer,
    tag: Buffer,
    ciphertext: Buffer
): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}