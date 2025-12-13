import net from 'net';
import fs from 'fs'
import path from 'path'
import { createECDH } from 'crypto';
import { deriveAesKeyFromSecret, aesGcmEncrypt } from './util.js';


export async function sendFile(senderPrivHex: string, senderPubHex: string, recipientPubHex: string, filePath: string, host: string, port: number) {
    const ecdh = createECDH('secp256k1');

    ecdh.setPrivateKey(Buffer.from(senderPrivHex, 'hex'));
    
    const recipientPubBuf = Buffer.from(recipientPubHex, 'hex');
    const secret = ecdh.computeSecret(recipientPubBuf);
    const aesKey = deriveAesKeyFromSecret(secret);
    const fileBuf = fs.readFileSync(filePath);

    const { iv, tag, ciphertext } = aesGcmEncrypt(aesKey, fileBuf);

    const envelope = {
        kind: 'ciphercast-v0.1.0',
        senderPub: senderPubHex,
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        filename: path.basename(filePath),
    };

    const payload = JSON.stringify(envelope);

    return new Promise<void>((resolve, reject) => {
        const socket = net.createConnection({ host, port }, () => {
    
            socket.write(Buffer.from(payload, 'utf-8'), () => {
                socket.end();
            });
        });

        socket.on('error', (err: Error) => reject(err));
        socket.on('close', () => resolve());
    });
}
