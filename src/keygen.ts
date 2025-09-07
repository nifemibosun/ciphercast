//@ts-ignore
import crypto from 'crypto';


export function genKeyPair(): any {
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.generateKeys();

    return {
        privateKey: ecdh.getPrivateKey("hex"),
        publicKey: ecdh.getPublicKey("hex")
    };

}