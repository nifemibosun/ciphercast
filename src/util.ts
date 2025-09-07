// @ts-ignore
import crypto from 'crypto';


//@ts-ignore
export function deriveAesKeyFromSecret(secret: Buffer) {
    return crypto.createHash('sha256').update(secret).digest();
}

//@ts-ignore
export function aesGcmEncrypt(aesKey: Buffer, plaintext: Buffer) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    //@ts-ignore
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return { iv, tag, ciphertext };
}

//@ts-ignore
export function aesGcmDecrypt(aesKey: Buffer, iv: Buffer, tag: Buffer, ciphertext: Buffer) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(tag);
    //@ts-ignore
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    return plain;
}
