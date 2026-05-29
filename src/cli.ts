#!/usr/bin/env node

import process from 'process';
import { genKeyPair } from './keygen.js';
import { sendFile } from './sender.js';
import { startReceiver } from './receiver.js';
import {
    saveIdentity,
    getIdentity,
    removeIdentity,
    listIdentities,
    addContact,
    removeContact,
    listContacts,
    resolvePubKey,
} from './keystore.js';


const ARRAY_FLAGS = new Set(['allow']);

interface ParsedArgs {
    cmd: string[];
    flags: Record<string, string | boolean | string[]>;
}

function parseArgs(argv: string[]): ParsedArgs {
    const cmd: string[] = [];
    const flags: Record<string, string | boolean | string[]> = {};

    let i = 0;
    while (i < argv.length) {
        const arg = argv[i] as string;

        if (arg.startsWith('--')) {
            const key = arg.slice(2);
            const next = argv[i + 1];
            const isBoolean = next === undefined || next.startsWith('--');

            if (isBoolean) {
                flags[key] = true;
                i += 1;
            } else if (ARRAY_FLAGS.has(key)) {
                if (!Array.isArray(flags[key])) flags[key] = [];
                (flags[key] as string[]).push(next);
                i += 2;
            } else {
                flags[key] = next;
                i += 2;
            }
        } else {
            cmd.push(arg);
            i += 1;
        }
    }

    return { cmd, flags };
}

/** Get a required string flag, throws a clear error if missing */
function requireFlag(flags: ParsedArgs['flags'], key: string): string {
    const val = flags[key];
    if (typeof val === 'string') return val;
    throw new Error(`Missing required flag: --${key}`);
}

/** Get a repeatable flag as an array (may be empty) */
function arrayFlag(flags: ParsedArgs['flags'], key: string): string[] {
    const val = flags[key];
    if (!val) return [];
    if (Array.isArray(val)) return val;
    return [val as string];
}


const HELP = `
CypherCast — P2P encrypted file transfer

USAGE
  ciphercast <command> [options]

COMMANDS
  keygen [--save <alias>]
      Generate a new key pair.
      With --save, the identity is stored under <alias> in the keystore.
      Without --save, prints the keys and exits (useful for one-offs).

  keys list
      Show all saved identities and contacts.

  keys add <alias> <pubhex>
      Save a contact's compressed public key under an alias.

  keys show <alias>
      Show keys for a saved identity, or the pubkey for a contact.

  keys rm <alias>
      Remove a saved identity from the keystore.

  keys contact rm <alias>
      Remove a saved contact from the keystore.

  recv --as <alias> --out <dir> --port <port>
       [--allow <alias|pubhex>...] [--overwrite]
      Start a receiver using the given identity.
      --allow can be repeated to build an allowlist of accepted senders.
      Omit --allow to accept from anyone (use with care on untrusted networks).
      --overwrite replaces existing files; without it a timestamp suffix is added.

  send --from <alias> --to <alias|pubhex> <file> <host> <port>
      Encrypt and send a file to a receiver.
`.trimStart();


async function cmdKeygen(flags: ParsedArgs['flags']): Promise<void> {
    const pair = genKeyPair();
    const saveAlias = flags['save'];

    if (typeof saveAlias === 'string') {
        saveIdentity(saveAlias, pair.privateKey, pair.publicKey);
        console.log(`Identity "${saveAlias}" saved to keystore.`);
        console.log(`Public Key : ${pair.publicKey}`);
        console.log(`\nShare your public key with people who will send you files.`);
    } else {
        console.log(`Private Key: ${pair.privateKey}`);
        console.log(`Public Key : ${pair.publicKey}`);
        console.log(`\nTip: use --save <alias> to store this identity for repeated use.`);
    }
}

function cmdKeys(subCmd: string[], cmd: string[]): void {
    switch (subCmd[0]) {
        case 'list': {
            const identities = listIdentities();
            const contacts = listContacts();

            console.log('\nIdentities:');
            const idEntries = Object.entries(identities);
            if (idEntries.length === 0) {
                console.log('  (none — run: ciphercast keygen --save <alias>)');
            } else {
                for (const [alias, id] of idEntries) {
                    console.log(`  ${alias}`);
                    console.log(`    pub: ${id.publicKey}`);
                }
            }

            console.log('\nContacts:');
            const contactEntries = Object.entries(contacts);
            if (contactEntries.length === 0) {
                console.log('  (none — run: ciphercast keys add <alias> <pubhex>)');
            } else {
                for (const [alias, pub] of contactEntries) {
                    console.log(`  ${alias}: ${pub}`);
                }
            }
            break;
        }

        case 'add': {
            const alias = cmd[2];
            const pubhex = cmd[3];
            if (!alias || !pubhex) {
                throw new Error('Usage: ciphercast keys add <alias> <pubhex>');
            }
            addContact(alias, pubhex);
            console.log(`Contact "${alias}" saved.`);
            break;
        }

        case 'show': {
            const alias = cmd[2];
            if (!alias) throw new Error('Usage: ciphercast keys show <alias>');

            const identity = getIdentity(alias);
            if (identity) {
                console.log(`Identity "${alias}"`);
                console.log(`  pub : ${identity.publicKey}`);
                console.log(`  priv: ${identity.privateKey}`);
                return;
            }

            const pub = resolvePubKey(alias);
            console.log(`Contact "${alias}": ${pub}`);
            break;
        }

        case 'rm': {
            const alias = cmd[2];
            if (!alias) throw new Error('Usage: ciphercast keys rm <alias>');
            removeIdentity(alias);
            console.log(`Identity "${alias}" removed.`);
            break;
        }

        case 'contact': {
            if (subCmd[1] === 'rm') {
                const alias = cmd[3];
                if (!alias) throw new Error('Usage: ciphercast keys contact rm <alias>');
                removeContact(alias);
                console.log(`Contact "${alias}" removed.`);
            } else {
                throw new Error(`Unknown subcommand: keys contact ${subCmd[1] ?? ''}`);
            }
            break;
        }

        default:
            throw new Error(
                `Unknown keys subcommand: "${subCmd[0]}"\n` +
                `Run \`ciphercast --help\` to see available commands.`
            );
    }
}

async function cmdSend(cmd: string[], flags: ParsedArgs['flags']): Promise<void> {
    const fromAlias = requireFlag(flags, 'from');
    const toArg = requireFlag(flags, 'to');
    const filePath = cmd[1];
    const host = cmd[2];
    const portStr = cmd[3];

    if (!filePath || !host || !portStr) {
        throw new Error(
            'Usage: ciphercast send --from <alias> --to <alias|pubhex> <file> <host> <port>'
        );
    }

    const port = parseInt(portStr, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
        throw new Error(`Invalid port: "${portStr}"`);
    }

    const senderIdentity = getIdentity(fromAlias);
    if (!senderIdentity) {
        throw new Error(
            `No identity named "${fromAlias}".\n` +
            `Create one with: ciphercast keygen --save ${fromAlias}`
        );
    }

    const recipientPubHex = resolvePubKey(toArg);

    console.log(`Sending "${filePath}" → ${host}:${port} ...`);

    await sendFile({
        senderPrivHex: senderIdentity.privateKey,
        senderPubHex: senderIdentity.publicKey,
        recipientPubHex,
        filePath,
        host,
        port,
    });

    console.log('Done — file sent successfully.');
}

function cmdRecv(cmd: string[], flags: ParsedArgs['flags']): void {
    void cmd;
    const asAlias = requireFlag(flags, 'as');
    const outDir = requireFlag(flags, 'out');
    const portStr = requireFlag(flags, 'port');

    const port = parseInt(portStr, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
        throw new Error(`Invalid port: "${portStr}"`);
    }

    const identity = getIdentity(asAlias);
    if (!identity) {
        throw new Error(
            `No identity named "${asAlias}".\n` +
            `Create one with: ciphercast keygen --save ${asAlias}`
        );
    }

    // Resolve each --allow value to a pubkey hex string
    const allowAliases = arrayFlag(flags, 'allow');
    const allowedSenders: string[] = allowAliases.map(a => resolvePubKey(a));

    const overwrite = flags['overwrite'] === true;

    startReceiver({
        receiverPrivHex: identity.privateKey,
        outDir,
        port,
        allowedSenders,
        overwrite,
    });
}


async function main(): Promise<void> {
    const rawArgs = process.argv.slice(2);

    if (rawArgs.length === 0 || rawArgs[0] === '--help' || rawArgs[0] === '-h') {
        process.stdout.write(HELP);
        return;
    }

    const { cmd, flags } = parseArgs(rawArgs);
    const command = cmd[0];

    switch (command) {
        case 'keygen':
            await cmdKeygen(flags);
            break;

        case 'keys':
            cmdKeys(cmd.slice(1), cmd);
            break;

        case 'send':
            await cmdSend(cmd, flags);
            break;

        case 'recv':
            cmdRecv(cmd, flags);
            break;

        default:
            throw new Error(
                `Unknown command: "${command}"\nRun \`ciphercast --help\` for usage.`
            );
    }
}

main().catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${msg}`);
    process.exit(1);
});