// @ts-ignore
import net from 'net';
//@ts-ignore
import fs from 'fs';
//@ts-ignore
import path from 'path';
//@ts-ignore
import { createECDH } from 'crypto';
import { deriveAesKeyFromSecret, aesGcmDecrypt } from './util';

export function startReceiver(receiverPrivHex: string, outDir: string, port: number) {
    const server = net.createServer((socket: any) => {
        //@ts-ignore
        let buffers: Buffer[] = [];
        //@ts-ignore
        socket.on('data', (chunk: Buffer) => {
            buffers.push(chunk);
        });

        socket.on('end', () => {
            try {
                //@ts-ignore
                const buffer = Buffer.concat(buffers);
                const payloadStr = buffer.toString('utf-8');
                const env = JSON.parse(payloadStr);
                if (env.kind !== 'ciphercast-v1') throw new Error('Bad envelope');

                const senderPubHex = env.senderPub;
                //@ts-ignore
                const iv = Buffer.from(env.iv, 'base64');
                //@ts-ignore
                const tag = Buffer.from(env.tag, 'base64');
                //@ts-ignore
                const ciphertext = Buffer.from(env.ciphertext, 'base64');
                const ecdh = createECDH('secp256k1');
                //@ts-ignore
                ecdh.setPrivateKey(Buffer.from(receiverPrivHex, 'hex'));
                //@ts-ignore
                const senderPubBuf = Buffer.from(senderPubHex, 'hex');
                const secret = ecdh.computeSecret(senderPubBuf);
                const aesKey = deriveAesKeyFromSecret(secret);
                const plaintext = aesGcmDecrypt(aesKey, iv, tag, ciphertext);

                const outPath = path.join(outDir, env.filename);
                fs.mkdirSync(outDir, { recursive: true });
                fs.writeFileSync(outPath, plaintext);
                socket.write(JSON.stringify({ ok: true, savedTo: outPath }));
            } catch (err) {
                socket.write(JSON.stringify({ ok: false, message: String(err) }));
            } finally {
                socket.end();
            }
        });

        socket.on('error', (err: Error) => console.error('Socket error', err));
    });

    server.listen(port, () => {
        console.log(`CypherCast receiver listening on port ${port}`);
    });

    return server;
}
