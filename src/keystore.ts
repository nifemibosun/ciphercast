import fs from 'fs'
import path from 'path';
import os from 'os';

const KEYSTORE_DIR = path.join(os.homedir(), '.ciphercast');
const KEYSTORE_PATH = path.join(KEYSTORE_DIR, 'keys.json');

const PUB_KEY_RE = /^[0-9a-fA-F]{66}$|^[0-9a-fA-F]{130}$/;

export interface Identity {
    privateKey: string;
    publicKey: string;
}

interface Keystore {
    identities: Record<string, Identity>;
    contacts: Record<string, string>;
}


function load(): Keystore {
    if (!fs.existsSync(KEYSTORE_PATH)) {
        return { identities: {}, contacts: {} };
    }
    try {
        const raw = fs.readFileSync(KEYSTORE_PATH, 'utf-8');
        return JSON.parse(raw) as Keystore;
    } catch {
        throw new Error(
            `Keystore at ${KEYSTORE_PATH} is corrupted. Inspect or delete it to continue.`
        );
    }
}

function save(ks: Keystore): void {
    fs.mkdirSync(KEYSTORE_DIR, { recursive: true });
    fs.writeFileSync(KEYSTORE_PATH, JSON.stringify(ks, null, 2), { mode: 0o600 });
}


export function saveIdentity(alias: string, privateKey: string, publicKey: string): void {
    const ks = load();
    ks.identities[alias] = { privateKey, publicKey };
    save(ks);
}

export function getIdentity(alias: string): Identity | null {
    return load().identities[alias] ?? null;
}

export function removeIdentity(alias: string): void {
    const ks = load();
    if (!(alias in ks.identities)) {
        throw new Error(`No identity named "${alias}"`);
    }
    delete ks.identities[alias];
    save(ks);
}

export function listIdentities(): Record<string, Identity> {
    return load().identities;
}


export function addContact(alias: string, pubKey: string): void {
    if (!PUB_KEY_RE.test(pubKey)) {
        throw new Error(
            `Invalid public key: "${pubKey}"\nExpected a 33-byte compressed (66 hex chars) or 65-byte uncompressed (130 hex chars) secp256k1 key.`
        );
    }
    const ks = load();
    ks.contacts[alias] = pubKey.toLowerCase();
    save(ks);
}

export function getContact(alias: string): string | null {
    return load().contacts[alias] ?? null;
}

export function removeContact(alias: string): void {
    const ks = load();
    if (!(alias in ks.contacts)) {
        throw new Error(`No contact named "${alias}"`);
    }
    delete ks.contacts[alias];
    save(ks);
}

export function listContacts(): Record<string, string> {
    return load().contacts;
}


/**
 * Resolves an alias or a raw hex pubkey to a pubkey hex string.
 * Resolution order: raw pubkey → contact alias → identity alias.
 * Throws a helpful error if nothing matches.
 */
export function resolvePubKey(aliasOrPub: string): string {
    if (PUB_KEY_RE.test(aliasOrPub)) {
        return aliasOrPub.toLowerCase();
    }
    const contact = getContact(aliasOrPub);
    if (contact) return contact;

    const identity = getIdentity(aliasOrPub);
    if (identity) return identity.publicKey;

    throw new Error(
        `Cannot resolve "${aliasOrPub}" — not a valid pubkey hex, contact, or identity.\n` +
        `Add as contact with: ciphercast keys add ${aliasOrPub} <pubhex>`
    );
}