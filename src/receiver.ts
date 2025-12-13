import net from 'net';
import fs from 'fs';
import path from 'path';
import { createECDH } from 'crypto';
import { deriveAesKeyFromSecret, aesGcmDecrypt } from './util.js';

export function startReceiver(receiverPrivHex: string, outDir: string, port: number) {
    const server = net.createServer((socket: any) => {
        let buffers: Buffer[] = [];
        socket.on('data', (chunk: Buffer) => {
            buffers.push(chunk);
        });

        socket.on('end', () => {
            try {
                const buffer = Buffer.concat(buffers);
                const payloadStr = buffer.toString('utf-8');
                const env = JSON.parse(payloadStr);

                if (env.kind !== 'ciphercast-v0.1.0') throw new Error('Bad envelope');

                const senderPubHex = env.senderPub;
                const iv = Buffer.from(env.iv, 'base64');
                const tag = Buffer.from(env.tag, 'base64');
                const ciphertext = Buffer.from(env.ciphertext, 'base64');
                const ecdh = createECDH('secp256k1');
    
                ecdh.setPrivateKey(Buffer.from(receiverPrivHex, 'hex'));
    
                const senderPubBuf = Buffer.from(senderPubHex, 'hex');
                const secret = ecdh.computeSecret(senderPubBuf);
                const aesKey = deriveAesKeyFromSecret(secret);
                const plaintext = aesGcmDecrypt(aesKey, iv, tag, ciphertext);

                const outPath = path.join(outDir, env.filename);
                fs.mkdirSync(outDir, { recursive: true });
                fs.writeFileSync(outPath, plaintext);
                console.log(`File received and saved as: ${outPath}`);
                socket.write(JSON.stringify({ ok: true, savedTo: outPath }));
            } catch (err) {
                socket.write(JSON.stringify({ ok: false, message: String(err) }));
            } finally {
                socket.end();
            }
        });

        socket.on('error', (err: Error) => console.error('Socket error', err));
    });

    server.listen(port, "::", () => {
        console.log(`CypherCast receiver listening on port ${port}`);
    });

    return server;
}
