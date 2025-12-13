import crypto from 'crypto';

export function deriveAesKeyFromSecret(secret: Buffer) {
    return crypto.createHash('sha256').update(secret).digest();
}
export function aesGcmEncrypt(aesKey: Buffer, plaintext: Buffer) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return { iv, tag, ciphertext };
}
export function aesGcmDecrypt(aesKey: Buffer, iv: Buffer, tag: Buffer, ciphertext: Buffer) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    return plain;
}
