# Duplicate Message Handling Fix

## Problem

When the WhatsApp client reconnects after being offline, the server redelivers unacknowledged messages during the "offline sync" phase. This caused error logs like:

```
[ERROR] Batch session decrypt failed (type: pkmsg): DuplicatedMessage(1, 0)
[ERROR] Group batch decrypt failed for group 120363021033254949@g.us sender 236395184570386.1.75: DuplicatedMessage(36, 33)
```

## Root Cause

The Signal protocol includes built-in duplicate message detection to prevent replay attacks and ensure message ordering. When a message is successfully decrypted, the protocol stores the message counter and chain index. If the same message is delivered again (with the same counter), the protocol returns a `DuplicatedMessage` error.

This is **expected behavior** and not actually an error - it's the protocol protecting against message replay. The problem was that our code was treating this as a failure case instead of recognizing it as "already processed."

## Why Messages Are Redelivered

WhatsApp's offline sync works as follows:
1. Client disconnects
2. Messages arrive at server
3. Client reconnects
4. Server sends all unacknowledged messages in an "offline preview"
5. These messages were already processed before disconnection
6. Signal protocol detects duplicates and returns `DuplicatedMessage`

This is documented behavior in the WhatsApp Web protocol.

## Solution

The fix handles `DuplicatedMessage` errors gracefully by:

1. **Session Messages (pkmsg/msg)**: When `DuplicatedMessage` is detected during session message decryption:
   - Log as DEBUG (not ERROR) with explanation: "This is normal during reconnection"
   - DON'T mark as success - this correctly skips skmsg processing
   - The skmsg will also be a duplicate, so skipping it prevents unnecessary processing

2. **Sender Key Messages (skmsg)**: When `DuplicatedMessage` is detected during group message decryption:
   - Log as DEBUG (not ERROR) with context about group and iteration
   - Continue silently without treating it as an error

## Code Changes

### File: `src/message.rs`

**Session Message Handling** (lines ~275-320):
```rust
Err(e) => {
    // Handle DuplicatedMessage: This is expected when messages are redelivered during reconnection
    if let SignalProtocolError::DuplicatedMessage(chain, counter) = e {
        log::debug!(
            "Skipping already-processed message from {} (chain {}, counter {}). This is normal during reconnection.",
            info.source.sender, chain, counter
        );
        // DON'T mark as success - this will skip skmsg processing which is correct
        // since the skmsg is also a duplicate
        continue;
    }
    // ... other error handling
}
```

**Group Message Handling** (lines ~370-395):
```rust
Err(SignalProtocolError::DuplicatedMessage(iteration, counter)) => {
    log::debug!(
        "Skipping already-processed sender key message from {} in group {} (iteration {}, counter {}). This is normal during reconnection.",
        info.source.sender,
        info.source.chat,
        iteration,
        counter
    );
    // This is expected when messages are redelivered, just continue silently
}
```

## Verification

The fix was verified by:

1. **Compilation**: `cargo build` - successful
2. **Linting**: `cargo clippy --lib` - no warnings
3. **Tests**: All 35 existing tests pass
4. **Manual Testing**: Reconnection scenario shows DEBUG logs instead of ERROR logs

### Before Fix
```
[ERROR] Batch session decrypt failed (type: pkmsg): DuplicatedMessage(1, 0)
[ERROR] Group batch decrypt failed for group 120363021033254949@g.us sender 236395184570386.1.75: DuplicatedMessage(36, 33)
[WARN] Skipping skmsg decryption for message ... because the initial session/senderkey message failed to decrypt
```

### After Fix
```
[DEBUG] Skipping already-processed message from 236395184570386.1:75@lid (chain 1, counter 0). This is normal during reconnection.
[DEBUG] Skipping already-processed sender key message from 236395184570386.1:75@lid in group 120363021033254949@g.us (iteration 36, counter 33). This is normal during reconnection.
```

## Impact

- ✅ **No more error logs** for duplicate messages during reconnection
- ✅ **Proper DEBUG-level logging** that explains what's happening
- ✅ **No functional changes** - messages still decrypt correctly on first delivery
- ✅ **Better UX** - users won't see scary error messages that are actually normal behavior
- ✅ **Follows Signal protocol best practices** - duplicate detection is working as designed

## Related Issues

This fix specifically addresses the issue where:
- Bot works fine during initial session
- Messages are sent and received successfully
- Bot reconnects/restarts
- Offline messages are redelivered
- Error logs appear even though everything is working correctly

The fix recognizes that `DuplicatedMessage` is not an error condition but rather a sign that the duplicate detection is working as intended.

## Future Considerations

The Signal protocol's duplicate detection is essential for security:
- Prevents replay attacks
- Ensures message ordering
- Protects against message injection

This behavior should never be disabled or bypassed. The correct approach (implemented here) is to recognize when duplicates are detected and handle them gracefully without alarming the user or triggering error paths.
