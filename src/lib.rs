extern crate byteorder;
extern crate digest;
extern crate murmurhash3;

use byteorder::ReadBytesExt;
use murmurhash3::murmurhash3_x86_32;

use std::io::{Error, ErrorKind};

/// Helper struct to provide read-only bit access to a slice of bytes.
struct BitSlice<'a> {
    /// The slice of bytes we're interested in.
    bytes: &'a [u8],
    /// The number of bits that are valid to access in the slice.
    /// Not necessarily equal to `bytes.len() * 8`, but it will not be greater than that.
    bit_len: usize,
}

impl<'a> BitSlice<'a> {
    /// Creates a new `BitSlice` of the given bit length over the given slice of data.
    /// Panics if the indicated bit length is larger than fits in the slice.
    ///
    /// # Arguments
    /// * `bytes` - The slice of bytes we need bit-access to
    /// * `bit_len` - The number of bits that are valid to access in the slice
    fn new(bytes: &'a [u8], bit_len: usize) -> BitSlice<'a> {
        if bit_len > bytes.len() * 8 {
            panic!(
                "bit_len too large for given data: {} > {} * 8",
                bit_len,
                bytes.len()
            );
        }
        BitSlice { bytes, bit_len }
    }

    /// Get the value of the specified bit.
    /// Panics if the specified bit is out of range for the number of bits in this instance.
    ///
    /// # Arguments
    /// * `bit_index` - The bit index to access
    fn get(&self, bit_index: usize) -> bool {
        if bit_index >= self.bit_len {
            panic!(
                "bit index out of range for bit slice: {} >= {}",
                bit_index, self.bit_len
            );
        }
        let byte_index = bit_index / 8;
        let final_bit_index = bit_index % 8;
        let byte = self.bytes[byte_index];
        let test_value = match final_bit_index {
            0 => byte & 0b00000001u8,
            1 => byte & 0b00000010u8,
            2 => byte & 0b00000100u8,
            3 => byte & 0b00001000u8,
            4 => byte & 0b00010000u8,
            5 => byte & 0b00100000u8,
            6 => byte & 0b01000000u8,
            7 => byte & 0b10000000u8,
            _ => panic!("impossible final_bit_index value: {}", final_bit_index),
        };
        test_value > 0
    }
}

/// A Bloom filter representing a specific level in a multi-level cascading Bloom filter.
struct Bloom<'a> {
    /// What level this filter is in
    level: u32,
    /// How many hash functions this filter uses
    n_hash_funcs: u32,
    /// The bit length of the filter
    size: usize,
    /// The data of the filter
    bit_slice: BitSlice<'a>,
}

const HASH_ALGORITHM_MURMUR_3: u8 = 1;

impl<'a> Bloom<'a> {
    /// Attempts to decode and return a pair that consists of the Bloom filter represented by the
    /// given bytes and any remaining unprocessed bytes in the given bytes.
    ///
    /// # Arguments
    /// * `bytes` - The encoded representation of this Bloom filter. May include additional data
    /// describing further Bloom filters. Any additional data is returned unconsumed.
    /// The format of an encoded Bloom filter is:
    /// [1 byte] - the hash algorithm to use in the filter
    /// [4 little endian bytes] - the length in bits of the filter
    /// [4 little endian bytes] - the number of hash functions to use in the filter
    /// [1 byte] - which level in the cascade this filter is
    /// [variable length bytes] - the filter itself (the length is determined by Ceiling(bit length
    /// / 8)
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(Bloom<'a>, &'a [u8]), Error> {
        let mut cursor = bytes;
        // Load the layer metadata. bloomer.py writes size, nHashFuncs and level as little-endian
        // unsigned ints.
        let hash_algorithm = cursor.read_u8()?;
        if hash_algorithm != HASH_ALGORITHM_MURMUR_3 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Invalid Bloom filter: unsupported algorithm ({})",
                    hash_algorithm
                ),
            ));
        }
        let size = cursor.read_u32::<byteorder::LittleEndian>()? as usize;
        let n_hash_funcs = cursor.read_u32::<byteorder::LittleEndian>()?;
        let level = cursor.read_u8()? as u32;

        let shifted_size = size.wrapping_shr(3);
        let byte_count = if size % 8 != 0 {
            shifted_size + 1
        } else {
            shifted_size
        };
        if byte_count > cursor.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid Bloom filter: too short",
            ));
        }
        let (bits_bytes, rest_of_bytes) = cursor.split_at(byte_count);
        let bloom = Bloom {
            level,
            n_hash_funcs,
            size,
            bit_slice: BitSlice::new(bits_bytes, size),
        };
        Ok((bloom, rest_of_bytes))
    }

    fn hash(&self, n_fn: u32, key: &[u8]) -> usize {
        let hash_seed = (n_fn << 16) + self.level;
        let h = murmurhash3_x86_32(key, hash_seed) as usize % self.size;
        h
    }

    /// Test for the presence of a given sequence of bytes in this Bloom filter.
    ///
    /// # Arguments
    /// `item` - The slice of bytes to test for
    pub fn has(&self, item: &[u8]) -> bool {
        for i in 0..self.n_hash_funcs {
            if !self.bit_slice.get(self.hash(i, item)) {
                return false;
            }
        }
        true
    }
}

/// A multi-level cascading Bloom filter.
pub struct Cascade<'a> {
    /// The Bloom filter for this level in the cascade
    filter: Bloom<'a>,
    /// The next (lower) level in the cascade
    child_layer: Option<Box<Cascade<'a>>>,
}

impl<'a> Cascade<'a> {
    /// Attempts to decode and return a multi-level cascading Bloom filter. NB: `Cascade` does not
    /// take ownership of the given data. This is to facilitate decoding cascading filters
    /// backed by memory-mapped files.
    ///
    /// # Arguments
    /// `bytes` - The encoded representation of the Bloom filters in this cascade. Starts with 2
    /// little endian bytes indicating the version. The current version is 1. See the documentation
    /// for `Bloom`. May be of length 0, in which case `None` is returned.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Option<Box<Cascade<'a>>>, Error> {
        if bytes.len() == 0 {
            return Ok(None);
        }
        let mut cursor = bytes;
        let version = cursor.read_u16::<byteorder::LittleEndian>()?;
        if version != 1 {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid version"));
        }
        Cascade::child_layer_from_bytes(cursor)
    }

    fn child_layer_from_bytes(bytes: &'a [u8]) -> Result<Option<Box<Cascade<'a>>>, Error> {
        let (filter, rest_of_bytes) = Bloom::from_bytes(bytes)?;
        Ok(Some(Box::new(Cascade {
            filter,
            child_layer: Cascade::from_bytes(rest_of_bytes)?,
        })))
    }

    /// Determine if the given sequence of bytes is in the cascade.
    ///
    /// # Arguments
    /// `entry` - The slice of bytes to test for
    pub fn has(&self, entry: &[u8]) -> bool {
        if self.filter.has(&entry) {
            match self.child_layer {
                Some(ref child) => {
                    let child_value = !child.has(entry);
                    return child_value;
                }
                None => {
                    return true;
                }
            }
        }
        return false;
    }
}

#[cfg(test)]
mod tests {
    use Bloom;
    use Cascade;

    #[test]
    fn bloom_test_from_bytes() {
        let src: Vec<u8> = vec![
            0x09, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x41, 0x00,
        ];

        match Bloom::from_bytes(&src) {
            Ok((bloom, rest_of_bytes)) => {
                assert!(rest_of_bytes.len() == 0);
                assert!(bloom.has(b"this") == true);
                assert!(bloom.has(b"that") == true);
                assert!(bloom.has(b"other") == false);
            }
            Err(_) => {
                panic!("Parsing failed");
            }
        };

        let short: Vec<u8> = vec![
            0x09, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x41,
        ];
        assert!(Bloom::from_bytes(&short).is_err());
    }

    #[test]
    fn bloom_test_from_file() {
        let v = include_bytes!("../test_data/test_bf");
        let (bloom, rest_of_bytes) = Bloom::from_bytes(v).expect("parsing Bloom should succeed");
        assert!(rest_of_bytes.len() == 0);
        assert!(bloom.has(b"this") == true);
        assert!(bloom.has(b"that") == true);
        assert!(bloom.has(b"yet another test") == false);
    }

    #[test]
    fn cascade_from_file_bytes_test() {
        let v = include_bytes!("../test_data/test_mlbf");
        let cascade = Cascade::from_bytes(v)
            .expect("parsing Cascade should succeed")
            .expect("Cascade should be Some");
        assert!(cascade.has(b"test") == true);
        assert!(cascade.has(b"another test") == true);
        assert!(cascade.has(b"yet another test") == true);
        assert!(cascade.has(b"blah") == false);
        assert!(cascade.has(b"blah blah") == false);
        assert!(cascade.has(b"blah blah blah") == false);

        let v = include_bytes!("../test_data/test_short_mlbf");
        assert!(Cascade::from_bytes(v).is_err());
    }
}
