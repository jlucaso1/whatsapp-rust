use flate2::{Decompress, FlushDecompress, Status};
use std::cell::RefCell;
use std::io;

thread_local! {
    static DECOMPRESSOR: RefCell<(Decompress, Vec<u8>)> = RefCell::new((
        Decompress::new(true),
        Vec::with_capacity(4096),
    ));
}

/// Decompress zlib data using a pooled decompressor.
///
/// Reuses the `flate2::Decompress` internal state (~48 KB) and the output
/// buffer across calls on the same thread, avoiding repeated heap allocations.
pub fn decompress_zlib_pooled(compressed: &[u8], max_size: u64) -> io::Result<Vec<u8>> {
    DECOMPRESSOR.with(|cell| {
        let (decompressor, scratch) = &mut *cell.borrow_mut();
        decompressor.reset(true);
        scratch.clear();

        let estimated = (compressed.len() * 4).clamp(256, 64 * 1024);
        if scratch.capacity() < estimated {
            scratch.reserve(estimated - scratch.capacity());
        }

        // Cap output growth to max_size + 1 so we detect oversized payloads
        // without allocating unbounded memory from a compressed bomb.
        let cap = (max_size as usize).saturating_add(1);

        let mut input_offset = 0;
        loop {
            // Enforce cap before decompress_vec can grow the buffer
            if scratch.len() >= cap {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("decompressed payload exceeds {max_size} bytes"),
                ));
            }

            let prev_in = decompressor.total_in();
            let prev_out = decompressor.total_out();

            let status = decompressor
                .decompress_vec(
                    &compressed[input_offset..],
                    scratch,
                    FlushDecompress::Finish,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            input_offset = decompressor.total_in() as usize;

            if scratch.len() as u64 > max_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("decompressed payload exceeds {max_size} bytes"),
                ));
            }

            match status {
                Status::StreamEnd => break,
                Status::Ok => {
                    // Grow but never past the cap
                    let want = scratch.capacity().max(4096).min(cap - scratch.len());
                    scratch.reserve(want);
                }
                Status::BufError => {
                    if decompressor.total_in() == prev_in && decompressor.total_out() == prev_out {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "zlib stream truncated (no progress)",
                        ));
                    }
                    let want = scratch.capacity().max(4096).min(cap - scratch.len());
                    scratch.reserve(want);
                }
            }
        }

        // Move the Vec out (zero-copy), then restore scratch with fresh capacity.
        // Callers (unpack_bytes, history_sync) wrap in Bytes::from() which takes
        // ownership of the Vec's allocation, so no extra copy occurs.
        let result = std::mem::take(scratch);
        // Pre-allocate for next call so the first decompress_vec doesn't start at 0
        scratch.reserve(4096);
        Ok(result)
    })
}
