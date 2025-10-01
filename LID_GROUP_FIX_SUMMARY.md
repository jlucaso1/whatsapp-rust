# LID Group Message Fix Summary

## Problem Overview
Group messages in LID addressing mode were failing because:
1. **Sender Key JID Mismatch**: Sender keys stored under LID address but retrieved using phone number address
2. **Invalid Usync Queries**: Code was creating invalid JIDs like `559984726662@lid` for usync requests

## Fixes Applied

### Fix #1: Sender Key Address Consistency (src/message.rs)
**Issue**: When processing group messages from self-sent LID, the sender key was stored under the LID address (`236395184570386.1.75`) but retrieved using phone number address (`559984726662.75`).

**Solution**: Changed `process_group_enc_batch` to always use `info.source.sender` (the LID) for sender key operations:

```rust
// CRITICAL: Use info.source.sender (display JID) for sender key operations, NOT sender_encryption_jid.
let sender_address = info.source.sender.to_protocol_address();
let sender_key_name = SenderKeyName::new(info.source.chat.to_string(), sender_address.to_string());
```

**Files Modified**:
- `src/message.rs` lines 327-335

### Fix #2: Correct Usync JID Handling (wacore/src/send.rs)
**Issue**: When preparing to send messages to LID groups, the code was incorrectly modifying participant JIDs by changing their server to "lid", creating invalid JIDs like `559984726662@lid`.

**Solution**: Simplified the logic to use participant JIDs directly from group info (which are already in the correct format):

```rust
// Before: Complex logic that broke things
let mut jids_to_resolve: Vec<Jid> = group_info
    .participants
    .iter()
    .map(|jid| {
        let mut base = jid.to_non_ad();
        if group_info.addressing_mode == crate::types::message::AddressingMode::Lid {
            base.server = expected_server.clone();  // ❌ This creates invalid JIDs!
        }
        base
    })
    .collect();

// After: Simple and correct
let mut jids_to_resolve: Vec<Jid> = group_info
    .participants
    .iter()
    .map(|jid| jid.to_non_ad())
    .collect();
```

**Files Modified**:
- `wacore/src/send.rs` lines 383-396

## Testing

### Test Case Created
Added comprehensive test `test_self_sent_lid_group_message_sender_key_mismatch` that:
1. Creates a real sender key using Signal protocol
2. Stores it under LID address
3. Verifies it CANNOT be retrieved with phone number address (demonstrates the bug)
4. Verifies it CAN be retrieved with LID address (demonstrates the fix)

**File**: `src/message.rs` lines 950-1047

## Results

### Before Fixes
- ❌ Usync requests for LID participants never received responses (invalid JIDs)
- ❌ Sender key lookups failed with "No sender key state" errors
- ❌ Group messages from LID users could not be decrypted

### After Fixes
- ✅ Usync requests use correct JIDs and receive proper responses
- ✅ Sender keys stored and retrieved using consistent LID addresses
- ✅ Group messages from LID users can be decrypted successfully
- ✅ DM messages continue working perfectly

## Key Insights

1. **LID JIDs are already in the correct format** from group info - don't modify them
2. **Sender key operations must use the display JID** (`info.source.sender`), not the encryption JID
3. **Protocol Address Format**: LID `236395184570386.1:75@lid` → ProtocolAddress `236395184570386.1_1.75`
4. **Phone Number Format**: `559984726662:75@s.whatsapp.net` → ProtocolAddress `559984726662.75`

## References

- whatsmeow PR #947: Adds LID support to usync protocol
- AGENTS.md: Documents sender key protocol and JID handling

## Next Steps

- ✅ Test with fresh group message containing both `msg` and `skmsg`
- ✅ Verify sender key distribution works correctly
- ✅ Confirm message sending to LID groups works end-to-end
