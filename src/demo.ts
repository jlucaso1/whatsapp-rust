/**
 * Simple demonstration script showing how to use the WASM Signal Repository
 */

import { 
    initSignalWasm, 
    makeLibSignalRepository, 
    MemorySignalKeyStore 
} from './Signal/libsignal.js';

async function demonstrateWasmSignal() {
    try {
        console.log('🚀 Initializing WASM Signal Protocol...');
        
        // Initialize the WASM module
        await initSignalWasm();
        console.log('✅ WASM module initialized');

        // Create a memory-based key store for demo
        const keyStore = new MemorySignalKeyStore();
        console.log('📦 Key store created');

        // Create the Signal Repository using WASM backend
        const signalRepo = makeLibSignalRepository(keyStore);
        console.log('🔐 Signal repository created');

        // Test basic functionality
        const testJid = "test@example.com";
        const testMessage = new TextEncoder().encode("Hello, WASM Signal Protocol!");

        console.log(`🔒 Attempting to encrypt message for ${testJid}...`);
        
        try {
            const encryptResult = await signalRepo.encryptMessage(testJid, testMessage);
            console.log('✅ Message encrypted successfully:', {
                type: encryptResult.type,
                ciphertextLength: encryptResult.ciphertext.length
            });
        } catch (error) {
            console.log('⚠️ Expected encryption failure (no session established):', error.message);
        }

        console.log('🎉 WASM Signal Protocol integration test completed!');
        
    } catch (error) {
        console.error('❌ Error during WASM Signal demonstration:', error);
    }
}

// Run the demonstration if this script is executed directly
if (typeof window !== 'undefined') {
    // Browser environment
    window.demonstrateWasmSignal = demonstrateWasmSignal;
    console.log('Demo function available as window.demonstrateWasmSignal()');
} else {
    // Node.js environment
    demonstrateWasmSignal().then(() => process.exit(0)).catch(console.error);
}

export { demonstrateWasmSignal };