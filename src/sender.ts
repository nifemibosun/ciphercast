import net from 'net';
import fs from 'fs';
import path from 'path';
import { createECDH } from 'crypto';
import { deriveAesKeyFromSecret, aesGcmEncrypt } from './util.js';

export interface SendOptions {
    senderPrivHex: string;
    senderPubHex: string;
    recipientPubHex: string;
    filePath: string;
    host: string;
    port: number;
}

interface ReceiverAck {
    ok: boolean;
    savedTo?: string;
    message?: string;
}

const ENVELOPE_VERSION = 'ciphercast-v0.1.1';

export async function sendFile(opts: SendOptions): Promise<void> {
    const { senderPrivHex, senderPubHex, recipientPubHex, filePath, host, port } = opts;

    if (!fs.existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
    }

    const ecdh = createECDH('secp256k1');
    ecdh.setPrivateKey(Buffer.from(senderPrivHex, 'hex'));
    const secret = ecdh.computeSecret(Buffer.from(recipientPubHex, 'hex'));
    const aesKey = deriveAesKeyFromSecret(secret);

    const fileBuf = fs.readFileSync(filePath);
    const { iv, tag, ciphertext } = aesGcmEncrypt(aesKey, fileBuf);

    const envelope = {
        kind: ENVELOPE_VERSION,
        senderPub: senderPubHex,
        filename: path.basename(filePath),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
    };

    const payload = Buffer.from(JSON.stringify(envelope), 'utf-8');

    return new Promise<void>((resolve, reject) => {
        const socket = net.createConnection({ host, port }, () => {
            socket.write(payload, () => socket.end());
        });

        let responseData = '';
        socket.on('data', (chunk: Buffer) => {
            responseData += chunk.toString('utf-8');
        });

        socket.on('end', () => {
            if (!responseData) {
                resolve();
                return;
            }
            try {
                const ack = JSON.parse(responseData) as ReceiverAck;
                if (!ack.ok) {
                    reject(new Error(ack.message ?? 'Receiver reported failure'));
                    return;
                }
                if (ack.savedTo) {
                    console.log(`  Receiver saved to: ${ack.savedTo}`);
                }
                resolve();
            } catch {
                resolve();
            }
        });

        socket.on('error', reject);
    });
}