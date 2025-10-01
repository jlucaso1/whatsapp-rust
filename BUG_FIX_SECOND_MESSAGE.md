# Bug Fix: Second Message in LID Group Not Decrypting

## Problem

After successfully sending the first message to a LID group, subsequent messages failed to decrypt with the warning:

```
Skipping skmsg decryption for message 3EB0E533C01E4C3E90E42C from 236395184570386.1:75@lid 
because the initial session/senderkey message failed to decrypt. This prevents a retry loop.
```

## Root Cause

The message handling logic in `src/message.rs` was incorrectly treating "no session establishment messages" as "session establishment failed".

### Message Structure

- **First message**: Contains `pkmsg` (session establishment) + `skmsg` (group content)
- **Subsequent messages**: Only contain `skmsg` (session already established)

### Buggy Logic

```rust
// Process session establishment messages (pkmsg/msg)
let session_decrypted_successfully = self
    .process_session_enc_batch(&session_enc_nodes, &info, &sender_encryption_jid)
    .await;

// Process group content (skmsg)
if session_decrypted_successfully {
    // Decrypt skmsg
} else {
    // Skip skmsg - BUG: This triggers even when there are NO session messages!
}
```

When `session_enc_nodes.is_empty()` (no `pkmsg`/`msg`), the function returns `false`, causing the code to skip `skmsg` decryption.

## Fix

Changed the logic to only skip `skmsg` if there WERE session messages that FAILED to decrypt:

```rust
// Only process group content if:
// 1. There were no session messages (session already exists), OR
// 2. Session messages were successfully decrypted
// Skip only if session messages FAILED to decrypt (not just absent)
if !group_content_enc_nodes.is_empty() {
    let should_process_skmsg = session_enc_nodes.is_empty() || session_decrypted_successfully;
    
    if should_process_skmsg {
        // Decrypt skmsg
    } else {
        // Skip skmsg (only when session messages FAILED)
    }
}
```

## Test Coverage

Added comprehensive test: `test_second_message_with_only_skmsg_decrypts`

**Test steps**:
1. Create and store a sender key (simulating first message processing)
2. Create a message with only `skmsg` (no `pkmsg`/`msg`)
3. Handle the message
4. Verify it's NOT skipped

## Verification

After the fix:
- ✅ First message: Decrypts successfully (with `pkmsg` + `skmsg`)
- ✅ Second message: Decrypts successfully (only `skmsg`)
- ✅ Subsequent messages: Continue working (only `skmsg`)
- ✅ All 35 tests passing

## Files Modified

- `src/message.rs`:
  - Fixed `handle_encrypted_message` logic (lines ~165-200)
  - Added test `test_second_message_with_only_skmsg_decrypts` (lines ~1540-1630)

## Impact

**Before fix**: Only the first message in a LID group conversation worked. All subsequent messages were skipped.

**After fix**: All messages work correctly, including the first and all subsequent messages.

---

**Date**: 2025-10-01  
**Branch**: feat-lid-definitive  
**Related Issue**: Second message in LID group not decrypting
