/**
 * Signal Protocol types and interfaces for the WhatsApp-Rust WASM integration.
 * This defines the API that the WASM Signal implementation should adhere to.
 */

export interface EncryptResult {
    /** The encrypted message data */
    ciphertext: Uint8Array;
    /** Message type (1 = PreKey, 2 = Regular, 3 = SenderKey) */
    type: number;
}

export interface DecryptResult {
    /** The decrypted plaintext data */
    plaintext: Uint8Array;
}

export interface PreKeyBundle {
    /** Identity key */
    identityKey: Uint8Array;
    /** Signed pre-key */
    signedPreKey: {
        keyId: number;
        publicKey: Uint8Array;
        signature: Uint8Array;
    };
    /** Pre-key (optional) */
    preKey?: {
        keyId: number;
        publicKey: Uint8Array;
    };
    /** Registration ID */
    registrationId: number;
}

export interface SignalAddress {
    /** User identifier (JID without device part) */
    name: string;
    /** Device ID */
    deviceId: number;
}

export interface SenderKeyName {
    /** Group identifier */
    groupId: string;
    /** Sender identifier */
    senderName: string;
}

/**
 * Key store interface that must be implemented in JavaScript
 * to provide persistence for the WASM Signal Protocol implementation.
 */
export interface SignalKeyStore {
    // Identity Key Store methods
    getIdentityKeyPair(): Promise<{ 
        publicKey: Uint8Array; 
        privateKey: Uint8Array; 
    }>;
    getLocalRegistrationId(): Promise<number>;
    saveIdentity(address: SignalAddress, identityKey: Uint8Array): Promise<void>;
    isTrustedIdentity(address: SignalAddress, identityKey: Uint8Array): Promise<boolean>;

    // Session Store methods
    loadSession(address: SignalAddress): Promise<Uint8Array | null>;
    storeSession(address: SignalAddress, record: Uint8Array): Promise<void>;
    containsSession(address: SignalAddress): Promise<boolean>;
    deleteSession(address: SignalAddress): Promise<void>;
    deleteAllSessions(name: string): Promise<void>;
    getSubDeviceSessions(name: string): Promise<number[]>;

    // Pre-Key Store methods
    loadPreKey(keyId: number): Promise<Uint8Array | null>;
    storePreKey(keyId: number, record: Uint8Array): Promise<void>;
    containsPreKey(keyId: number): Promise<boolean>;
    removePreKey(keyId: number): Promise<void>;

    // Signed Pre-Key Store methods
    loadSignedPreKey(keyId: number): Promise<Uint8Array | null>;
    loadSignedPreKeys(): Promise<Uint8Array[]>;
    storeSignedPreKey(keyId: number, record: Uint8Array): Promise<void>;
    containsSignedPreKey(keyId: number): Promise<boolean>;
    removeSignedPreKey(keyId: number): Promise<void>;

    // Sender Key Store methods
    storeSenderKey(senderKeyName: SenderKeyName, record: Uint8Array): Promise<void>;
    loadSenderKey(senderKeyName: SenderKeyName): Promise<Uint8Array>;
    deleteSenderKey(senderKeyName: SenderKeyName): Promise<void>;
}

/**
 * Main Signal Repository interface that provides encryption/decryption
 * and session management functionality.
 */
export interface SignalRepository {
    /**
     * Encrypt a message for 1-on-1 communication
     */
    encryptMessage(jid: string, plaintext: Uint8Array): Promise<EncryptResult>;

    /**
     * Decrypt a message from 1-on-1 communication
     */
    decryptMessage(
        jid: string, 
        ciphertext: Uint8Array, 
        messageType: number
    ): Promise<DecryptResult>;

    /**
     * Encrypt a message for group communication
     */
    encryptGroupMessage(
        groupId: string,
        senderKeyId: string,
        plaintext: Uint8Array
    ): Promise<EncryptResult>;

    /**
     * Decrypt a message from group communication
     */
    decryptGroupMessage(
        groupId: string,
        senderKeyId: string,
        ciphertext: Uint8Array
    ): Promise<DecryptResult>;

    /**
     * Inject a new E2E session using a pre-key bundle
     */
    injectE2ESession(jid: string, preKeyBundle: PreKeyBundle): Promise<void>;

    /**
     * Process a sender key distribution message for group communication
     */
    processSenderKeyDistributionMessage(
        senderKeyId: string,
        distributionMessage: Uint8Array
    ): Promise<void>;
}