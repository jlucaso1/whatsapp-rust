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

        let mut input_offset = 0;
        loop {
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
                Status::Ok | Status::BufError => {
                    // Need more output space
                    scratch.reserve(scratch.capacity().max(4096));
                }
            }
        }

        // Return the data by swapping out to avoid cloning.
        // The scratch buffer keeps its capacity for the next call.
        let mut result = Vec::new();
        std::mem::swap(scratch, &mut result);
        Ok(result)
    })
}
