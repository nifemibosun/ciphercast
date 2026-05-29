import net from 'net';
import fs from 'fs';
import path from 'path';
import { createECDH } from 'crypto';
import { deriveAesKeyFromSecret, aesGcmDecrypt } from './util.js';

export interface ReceiverOptions {
    receiverPrivHex: string;
    outDir: string;
    port: number;
    allowedSenders?: string[];
    overwrite?: boolean;
}

const ENVELOPE_VERSION = 'ciphercast-v0.1.1';

function resolveOutPath(outDir: string, filename: string, overwrite: boolean): string {
    const outPath = path.join(outDir, filename);
    if (overwrite || !fs.existsSync(outPath)) return outPath;

    const ext = path.extname(filename);
    const base = path.basename(filename, ext);
    return path.join(outDir, `${base}_${Date.now()}${ext}`);
}

export function startReceiver(opts: ReceiverOptions): net.Server {
    const {
        receiverPrivHex,
        outDir,
        port,
        allowedSenders = [],
        overwrite = false,
    } = opts;

    const allowSet = new Set(allowedSenders.map(k => k.toLowerCase()));

    const server = net.createServer((socket: net.Socket) => {
        const remote = `${socket.remoteAddress}:${socket.remotePort}`;
        console.log(`[+] Connection from ${remote}`);

        const chunks: Buffer[] = [];

        socket.on('data', (chunk: Buffer) => chunks.push(chunk));

        socket.on('end', () => {
            const ack = (ok: boolean, payload: string) => {
                const msg = ok
                    ? JSON.stringify({ ok: true, savedTo: payload })
                    : JSON.stringify({ ok: false, message: payload });
                socket.write(msg);
                socket.end();
            };

            try {
                const raw = Buffer.concat(chunks).toString('utf-8');
                const env = JSON.parse(raw) as Record<string, string>;

                if (env['kind'] !== ENVELOPE_VERSION) {
                    throw new Error(`Unsupported envelope version: "${env['kind']}"`);
                }

                const senderPubHex = env['senderPub']?.toLowerCase();
                if (!senderPubHex) throw new Error('Envelope missing senderPub');

                // sender allowlist check
                if (allowSet.size > 0 && !allowSet.has(senderPubHex)) {
                    console.warn(`[-] Rejected — sender not in allowlist: ${senderPubHex}`);
                    ack(false, 'Sender not in allowlist');
                    return;
                }

                // ECDH key exchange
                const ecdh = createECDH('secp256k1');
                ecdh.setPrivateKey(Buffer.from(receiverPrivHex, 'hex'));
                const secret = ecdh.computeSecret(Buffer.from(senderPubHex, 'hex'));
                const aesKey = deriveAesKeyFromSecret(secret);

                // decrypt
                const iv = Buffer.from(env['iv']!, 'base64');
                const tag = Buffer.from(env['tag']!, 'base64');
                const ciphertext = Buffer.from(env['ciphertext']!, 'base64');
                const plaintext = aesGcmDecrypt(aesKey, iv, tag, ciphertext);

                // write
                fs.mkdirSync(outDir, { recursive: true });
                const outPath = resolveOutPath(outDir, env['filename']!, overwrite);
                fs.writeFileSync(outPath, plaintext);

                console.log(`[+] Saved: ${outPath}`);
                ack(true, outPath);
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                console.error(`[-] Failed to process file: ${msg}`);
                ack(false, msg);
            }
        });

        socket.on('error', (err: Error) => {
            console.error(`[-] Socket error: ${err.message}`);
        });
    });

    server.listen(port, '0.0.0.0', () => {
        console.log(`[*] CypherCast receiver listening on 0.0.0.0:${port}`);
        if (allowSet.size > 0) {
            console.log(`[*] Accepting ${allowSet.size} known sender(s)`);
        } else {
            console.log('[!] No allowlist set — accepting files from any sender');
        }
    });

    return server;
}