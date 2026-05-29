import crypto from 'crypto';

export interface KeyPair {
    privateKey: string;
    publicKey: string;
}

export function genKeyPair(): KeyPair {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();
    return {
        privateKey: ecdh.getPrivateKey('hex'),
        publicKey: ecdh.getPublicKey('hex', 'compressed'),
    };
}