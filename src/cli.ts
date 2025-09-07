#!/usr/bin/env node

//@ts-ignore
import process from 'process';

import { genKeyPair } from './keygen';
import { sendFile } from "./sender";
import { startReceiver } from "./receiver";


function main(): void {
    const args = process.argv.slice();

    if (args.length < 3 || args.length > 9) {
        console.error('Incorrect Arguments');
        return;
    }

    switch (args[2]) {
        case "keygen":
            console.log("Private Key: ", genKeyPair().privateKey);
            console.log("Public Key: ", genKeyPair().publicKey);
            break;

        case "recv":
            if (!args[3] || !args[4] || !args[5]) {
                throw new Error("Usage: ciphercast recv <receiverPrivHex> <outDir> <port>");
            }
            const recvPrivHex = args[3];
            const outDir = args[4];
            const port = parseInt(args[5], 10);
            console.log("Waiting for sender...");
            startReceiver(recvPrivHex, outDir, port);
            break;

        case "send":
            if (!args[3] || !args[4] || !args[5] || !args[6] || !args[7]) {
                throw new Error("Usage: ciphercast send <senderPrivHex> <senderPubHex> <recipientPubHex> <file> <host> <port>");
            }
            const senderPrivHex = args[3];
            const senderPubHex = args[4];
            const recipientPubHex = args[5];
            const fileNameSend = args[6];
            const host = args[7];
            const portSend = parseInt(args[8], 10);

            console.log(`Sending encrypted ${fileNameSend} to ${host}:${portSend}...`);
            sendFile(senderPrivHex, senderPubHex, recipientPubHex, fileNameSend, host, portSend)
                .then(() => console.log("File sent successfully"))
                .catch((err) => console.error("Send failed:", err));
            break;

        default:
            console.error("Unknown command:", args[2]);
            break;
    }
}


main();