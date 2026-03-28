//! Minimal store-only ZIP writer. No compression, no streaming.

const LOCAL_FILE_HEADER_SIG: u32 = 0x04034b50;
const CENTRAL_DIR_SIG: u32 = 0x02014b50;
const END_OF_CENTRAL_DIR_SIG: u32 = 0x06054b50;
const VERSION: u16 = 20;

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_zero_u16s(buf: &mut Vec<u8>, n: usize) {
    for _ in 0..n {
        put_u16(buf, 0);
    }
}

struct Entry {
    name: Vec<u8>,
    offset: u32,
    crc32: u32,
    size: u32,
}

pub(crate) struct ZipWriter {
    buf: Vec<u8>,
    entries: Vec<Entry>,
}

impl ZipWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            entries: Vec::new(),
        }
    }

    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        let name_bytes = name.as_bytes();
        let crc = crc32(data);
        let size = data.len() as u32;
        let offset = self.buf.len() as u32;

        put_u32(&mut self.buf, LOCAL_FILE_HEADER_SIG);
        put_u16(&mut self.buf, VERSION);
        put_zero_u16s(&mut self.buf, 3); // flags, method (stored), mod time
        put_u16(&mut self.buf, 0); // mod date
        put_u32(&mut self.buf, crc);
        put_u32(&mut self.buf, size); // compressed
        put_u32(&mut self.buf, size); // uncompressed
        put_u16(&mut self.buf, name_bytes.len() as u16);
        put_u16(&mut self.buf, 0); // extra field len
        self.buf.extend_from_slice(name_bytes);
        self.buf.extend_from_slice(data);

        self.entries.push(Entry {
            name: name_bytes.to_vec(),
            offset,
            crc32: crc,
            size,
        });
    }

    pub fn finish(mut self) -> Vec<u8> {
        let cd_offset = self.buf.len() as u32;

        for e in &self.entries {
            put_u32(&mut self.buf, CENTRAL_DIR_SIG);
            put_u16(&mut self.buf, VERSION); // made by
            put_u16(&mut self.buf, VERSION); // needed
            put_zero_u16s(&mut self.buf, 2); // flags, method
            put_zero_u16s(&mut self.buf, 2); // mod time, mod date
            put_u32(&mut self.buf, e.crc32);
            put_u32(&mut self.buf, e.size); // compressed
            put_u32(&mut self.buf, e.size); // uncompressed
            put_u16(&mut self.buf, e.name.len() as u16);
            put_zero_u16s(&mut self.buf, 4); // extra len, comment len, disk start, internal attrs
            put_u32(&mut self.buf, 0); // external attrs
            put_u32(&mut self.buf, e.offset);
            self.buf.extend_from_slice(&e.name);
        }

        let cd_size = self.buf.len() as u32 - cd_offset;
        let count = self.entries.len() as u16;

        put_u32(&mut self.buf, END_OF_CENTRAL_DIR_SIG);
        put_zero_u16s(&mut self.buf, 2); // disk number, disk with cd
        put_u16(&mut self.buf, count);
        put_u16(&mut self.buf, count);
        put_u32(&mut self.buf, cd_size);
        put_u32(&mut self.buf, cd_offset);
        put_u16(&mut self.buf, 0); // comment len

        self.buf
    }
}

fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(|| {
        let mut table = [0u32; 256];
        for i in 0..256u32 {
            let mut crc = i;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = 0xEDB88320 ^ (crc >> 1);
                } else {
                    crc >>= 1;
                }
            }
            table[i as usize] = crc;
        }
        table
    });

    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_values() {
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn zip_single_file() {
        let mut w = ZipWriter::new();
        w.add_file("hello.txt", b"Hello, world!");
        let zip = w.finish();

        assert_eq!(&zip[0..4], &LOCAL_FILE_HEADER_SIG.to_le_bytes());
        let eocd_pos = zip.len() - 22;
        assert_eq!(
            &zip[eocd_pos..eocd_pos + 4],
            &END_OF_CENTRAL_DIR_SIG.to_le_bytes()
        );
        assert_eq!(
            u16::from_le_bytes([zip[eocd_pos + 8], zip[eocd_pos + 9]]),
            1
        );
    }

    #[test]
    fn zip_multiple_files() {
        let mut w = ZipWriter::new();
        w.add_file("a.bin", &[0xAA; 100]);
        w.add_file("b.bin", &[0xBB; 200]);
        w.add_file("c.bin", &[0xCC; 50]);
        let zip = w.finish();

        let eocd_pos = zip.len() - 22;
        assert_eq!(
            u16::from_le_bytes([zip[eocd_pos + 8], zip[eocd_pos + 9]]),
            3
        );
    }

    #[test]
    fn central_directory_offsets_valid() {
        let data = b"test content here";
        let mut w = ZipWriter::new();
        w.add_file("test.bin", data);
        let zip = w.finish();

        // Parse EOCD to find central directory
        let eocd_pos = zip.len() - 22;
        let cd_offset =
            u32::from_le_bytes(zip[eocd_pos + 16..eocd_pos + 20].try_into().unwrap()) as usize;

        // Central directory entry should start with its signature
        assert_eq!(
            &zip[cd_offset..cd_offset + 4],
            &CENTRAL_DIR_SIG.to_le_bytes()
        );

        // Parse central directory entry to extract local header offset (at fixed offset 42)
        let local_offset =
            u32::from_le_bytes(zip[cd_offset + 42..cd_offset + 46].try_into().unwrap()) as usize;
        assert_eq!(local_offset, 0);

        // Local header should contain the original data
        let name_len = u16::from_le_bytes(
            zip[local_offset + 26..local_offset + 28]
                .try_into()
                .unwrap(),
        ) as usize;
        let data_start = local_offset + 30 + name_len;
        assert_eq!(&zip[data_start..data_start + data.len()], data);
    }
}
