extern crate byteorder;
extern crate murmurhash3;
extern crate sha2;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use murmurhash3::murmurhash3_x86_32;
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::{Error, ErrorKind, Read};
use std::mem::size_of;

/// Helper struct to provide read-only bit access to a vector of bytes.
struct BitVector {
    /// The bytes we're interested in.
    bytes: Vec<u8>,
    /// The number of bits that are valid to access in the vector.
    /// Not necessarily equal to `bytes.len() * 8`, but it will not be greater than that.
    bit_len: usize,
}

impl BitVector {
    /// Creates a new `BitVector` of the given bit length over the given data.
    /// Panics if the indicated bit length is larger than fits in the vector.
    ///
    /// # Arguments
    /// * `bytes` - The bytes we need bit-access to
    /// * `bit_len` - The number of bits that are valid to access in the vector
    fn new(bytes: Vec<u8>, bit_len: usize) -> BitVector {
        if bit_len > bytes.len() * 8 {
            panic!(
                "bit_len too large for given data: {} > {} * 8",
                bit_len,
                bytes.len()
            );
        }
        BitVector { bytes, bit_len }
    }

    /// Get the value of the specified bit.
    /// Panics if the specified bit is out of range for the number of bits in this instance.
    ///
    /// # Arguments
    /// * `bit_index` - The bit index to access
    fn get(&self, bit_index: usize) -> bool {
        if bit_index >= self.bit_len {
            panic!(
                "bit index out of range for bit vector: {} >= {}",
                bit_index, self.bit_len
            );
        }
        let byte_index = bit_index / 8;
        let final_bit_index = bit_index % 8;
        let byte = self.bytes[byte_index];
        let test_value = match final_bit_index {
            0 => byte & 0b0000_0001u8,
            1 => byte & 0b0000_0010u8,
            2 => byte & 0b0000_0100u8,
            3 => byte & 0b0000_1000u8,
            4 => byte & 0b0001_0000u8,
            5 => byte & 0b0010_0000u8,
            6 => byte & 0b0100_0000u8,
            7 => byte & 0b1000_0000u8,
            _ => panic!("impossible final_bit_index value: {}", final_bit_index),
        };
        test_value > 0
    }
}

/// A Bloom filter representing a specific level in a multi-level cascading Bloom filter.
struct Bloom {
    /// What level this filter is in
    level: u8,
    /// How many hash functions this filter uses
    n_hash_funcs: u32,
    /// The bit length of the filter
    size: u32,
    /// The data of the filter
    bit_vector: BitVector,
    /// The hash algorithm enumeration in use
    hash_algorithm: HashAlgorithm,
}

#[repr(u8)]
#[derive(Copy, Clone)]
/// These enumerations need to match the python filter-cascade project:
/// https://github.com/mozilla/filter-cascade/blob/v0.3.0/filtercascade/fileformats.py
enum HashAlgorithm {
    MurmurHash3 = 1,
    Sha256l32 = 2, // low 32 bits of sha256
    Sha256 = 3,    // all 256 bits of sha256
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", *self as u8)
    }
}

impl TryFrom<u8> for HashAlgorithm {
    type Error = ();
    fn try_from(value: u8) -> Result<HashAlgorithm, ()> {
        match value {
            // Naturally, these need to match the enum declaration
            1 => Ok(Self::MurmurHash3),
            2 => Ok(Self::Sha256l32),
            3 => Ok(Self::Sha256),
            _ => Err(()),
        }
    }
}

/// A CascadeIndexGenerator provides read-once access to a table
/// of numbers H_ij with 0 <= H_ij < r_i.
///
/// A call to next_layer(r) increments i and sets r_i = r.
/// A call to next_index() increments j and outputs H_ij.
///
trait CascadeIndexGenerator {
    fn next_layer(&mut self, size: u32);
    fn next_index(&mut self) -> usize;
}

struct MurmurHash3IndexGenerator<'a> {
    key: &'a [u8],
    counter: u32,
    depth: u32,
    range: u32,
}

impl<'a> MurmurHash3IndexGenerator<'a> {
    fn new(key: &'a [u8], top_layer_size: u32) -> Self {
        MurmurHash3IndexGenerator {
            key,
            counter: 0,
            depth: 1,
            range: top_layer_size,
        }
    }
}

impl<'a> CascadeIndexGenerator for MurmurHash3IndexGenerator<'a> {
    fn next_index(&mut self) -> usize {
        let hash_seed = (self.counter << 16) + self.depth;
        self.counter += 1;
        let index = murmurhash3_x86_32(self.key, hash_seed);
        (index % self.range) as usize
    }
    fn next_layer(&mut self, size: u32) {
        self.counter = 0;
        self.depth += 1;
        self.range = size;
    }
}

struct SHA256l32IndexGenerator<'a> {
    salt: &'a [u8],
    key: &'a [u8],
    counter: u32,
    depth: u8,
    range: u32,
}

impl<'a> SHA256l32IndexGenerator<'a> {
    fn new(salt: &'a [u8], key: &'a [u8], top_layer_size: u32) -> Self {
        SHA256l32IndexGenerator {
            salt,
            key,
            counter: 0,
            depth: 1,
            range: top_layer_size,
        }
    }
}

impl<'a> CascadeIndexGenerator for SHA256l32IndexGenerator<'a> {
    fn next_index(&mut self) -> usize {
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(self.counter.to_le_bytes());
        hasher.update(self.depth.to_le_bytes());
        hasher.update(self.key);
        self.counter += 1;
        let index = u32::from_le_bytes(
            hasher.finalize()[0..4]
                .try_into()
                .expect("sha256 should have given enough bytes"),
        );
        (index % self.range) as usize
    }
    fn next_layer(&mut self, size: u32) {
        self.counter = 0;
        self.depth += 1;
        self.range = size;
    }
}

struct SHA256CtrIndexGenerator<'a> {
    salt: &'a [u8],
    key: &'a [u8],
    counter: u32,
    range: u32,
    state: [u8; 32],
    state_available: usize,
}

impl<'a> SHA256CtrIndexGenerator<'a> {
    fn new(salt: &'a [u8], key: &'a [u8], top_layer_size: u32) -> Self {
        SHA256CtrIndexGenerator {
            salt,
            key,
            counter: 0,
            range: top_layer_size,
            state: [0; 32],
            state_available: 0,
        }
    }
}

impl<'a> CascadeIndexGenerator for SHA256CtrIndexGenerator<'a> {
    fn next_index(&mut self) -> usize {
        // |bytes_needed| is the minimum number of bytes needed to represent a value in [0, range).
        let bytes_needed = ((self.range.next_power_of_two().trailing_zeros() + 7) / 8) as usize;
        let mut index_arr = [0u8; 4];
        for byte in index_arr.iter_mut().take(bytes_needed) {
            if self.state_available == 0 {
                let mut hasher = Sha256::new();
                hasher.update(self.counter.to_le_bytes());
                hasher.update(self.salt);
                hasher.update(self.key);
                let digest = &hasher.finalize()[..];
                self.state.copy_from_slice(digest);
                self.state_available = 32;
                self.counter += 1;
            }
            *byte = self.state[32 - self.state_available];
            self.state_available -= 1;
        }
        let index = LittleEndian::read_u32(&index_arr);
        (index % self.range) as usize
    }
    fn next_layer(&mut self, size: u32) {
        self.range = size;
    }
}

impl Bloom {
    /// Attempts to decode the Bloom filter represented by the bytes in the given reader.
    ///
    /// # Arguments
    /// * `reader` - The encoded representation of this Bloom filter. May be empty. May include
    /// additional data describing further Bloom filters.
    /// The format of an encoded Bloom filter is:
    /// [1 byte] - the hash algorithm to use in the filter
    /// [4 little endian bytes] - the length in bits of the filter
    /// [4 little endian bytes] - the number of hash functions to use in the filter
    /// [1 byte] - which level in the cascade this filter is
    /// [variable length bytes] - the filter itself (the length is determined by Ceiling(bit length
    /// / 8)
    pub fn read<R: Read>(reader: &mut R) -> Result<Option<Bloom>, Error> {
        // Load the layer metadata. bloomer.py writes size, nHashFuncs and level as little-endian
        // unsigned ints.
        let hash_algorithm_val = match reader.read_u8() {
            Ok(val) => val,
            // If reader is at EOF, there is no bloom filter.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        };
        let hash_algorithm = match HashAlgorithm::try_from(hash_algorithm_val) {
            Ok(algo) => algo,
            Err(()) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Unexpected hash algorithm",
                ))
            }
        };

        let size = reader.read_u32::<byteorder::LittleEndian>()?;
        let n_hash_funcs = reader.read_u32::<byteorder::LittleEndian>()?;
        let level = reader.read_u8()?;

        let byte_count = ((size + 7) / 8) as usize;
        let mut bits_bytes = vec![0; byte_count];
        reader.read_exact(&mut bits_bytes)?;
        let bloom = Bloom {
            level,
            n_hash_funcs,
            size,
            bit_vector: BitVector::new(bits_bytes, size as usize),
            hash_algorithm,
        };
        Ok(Some(bloom))
    }

    /// Test for the presence of a given sequence of bytes in this Bloom filter.
    ///
    /// # Arguments
    /// `item` - The slice of bytes to test for
    fn has<T: CascadeIndexGenerator>(&self, generator: &mut T) -> bool {
        for _ in 0..self.n_hash_funcs {
            if !self.bit_vector.get(generator.next_index()) {
                return false;
            }
        }
        true
    }
}

impl fmt::Display for Bloom {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "level={} n_hash_funcs={} hash_algorithm={} size={}",
            self.level, self.n_hash_funcs, self.hash_algorithm, self.size
        )
    }
}

/// A multi-level cascading Bloom filter.
pub struct Cascade {
    /// The Bloom filter for this level in the cascade
    filter: Bloom,
    /// The next (lower) level in the cascade
    child_layer: Option<Box<Cascade>>,
    /// The salt in use, if any
    salt: Vec<u8>,
    /// Whether the logic should be inverted
    inverted: bool,
}

impl Cascade {
    /// Attempts to decode and return a multi-level cascading Bloom filter.
    ///
    /// # Arguments
    /// `bytes` - The encoded representation of the Bloom filters in this cascade. Starts with 2
    /// little endian bytes indicating the version. The current version is 2. The Python
    /// filter-cascade project defines the formats, see
    /// https://github.com/mozilla/filter-cascade/blob/v0.3.0/filtercascade/fileformats.py
    ///
    /// May be of length 0, in which case `None` is returned.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Option<Box<Cascade>>, Error> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let mut reader = bytes.as_slice();
        let version = reader.read_u16::<byteorder::LittleEndian>()?;
        let mut salt = vec![];
        let mut inverted = false;

        if version >= 2 {
            inverted = reader.read_u8()? != 0;
            let salt_len = reader.read_u8()? as usize;
            if salt_len > 0 {
                let mut salt_bytes = vec![0; salt_len];
                reader.read_exact(&mut salt_bytes)?;
                salt.extend_from_slice(&salt_bytes);
            }
        }

        if version > 2 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid version: {}", version),
            ));
        }

        Cascade::child_layer_from_bytes(reader, &salt, inverted)
    }

    fn child_layer_from_bytes<R: Read>(
        mut reader: R,
        salt: &[u8],
        inverted: bool,
    ) -> Result<Option<Box<Cascade>>, Error> {
        let filter = match Bloom::read(&mut reader)? {
            Some(filter) => filter,
            None => return Ok(None),
        };
        Ok(Some(Box::new(Cascade {
            filter,
            child_layer: Cascade::child_layer_from_bytes(reader, salt, inverted)?,
            salt: salt.to_vec(),
            inverted,
        })))
    }

    /// Determine if the given sequence of bytes is in the cascade.
    ///
    /// # Arguments
    /// `entry` - The slice of bytes to test for
    pub fn has(&self, entry: &[u8]) -> bool {
        let result = match self.filter.hash_algorithm {
            HashAlgorithm::MurmurHash3 => {
                assert!(self.salt.is_empty());
                self.has_internal(&mut MurmurHash3IndexGenerator::new(entry, self.filter.size))
            }
            HashAlgorithm::Sha256l32 => self.has_internal(&mut SHA256l32IndexGenerator::new(
                &self.salt,
                entry,
                self.filter.size,
            )),
            HashAlgorithm::Sha256 => self.has_internal(&mut SHA256CtrIndexGenerator::new(
                &self.salt,
                entry,
                self.filter.size,
            )),
        };
        if self.inverted {
            return !result;
        }
        result
    }

    fn has_internal<T: CascadeIndexGenerator>(&self, generator: &mut T) -> bool {
        if self.filter.has(generator) {
            match self.child_layer {
                Some(ref child) => {
                    generator.next_layer(child.filter.size);
                    let child_value = !child.has_internal(generator);
                    return child_value;
                }
                None => {
                    return true;
                }
            }
        }
        false
    }

    /// Determine the approximate amount of memory in bytes used by this
    /// Cascade. Because this implementation does not integrate with the
    /// allocator, it can't get an accurate measurement of how much memory it
    /// uses. However, it can make a reasonable guess, assuming the sizes of
    /// the bloom filters are large enough to dominate the overall allocated
    /// size.
    pub fn approximate_size_of(&self) -> usize {
        size_of::<Cascade>()
            + self.filter.bit_vector.bytes.len()
            + self
                .child_layer
                .as_ref()
                .map_or(0, |child_layer| child_layer.approximate_size_of())
            + self.salt.len()
    }
}

impl fmt::Display for Cascade {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "salt={:?} inverted={} filter=[{}] ",
            self.salt, self.inverted, self.filter
        )?;
        match &self.child_layer {
            Some(layer) => write!(f, "[child={}]", layer),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use Bloom;
    use Cascade;
    use MurmurHash3IndexGenerator;

    #[test]
    fn bloom_v1_test_from_bytes() {
        let src: Vec<u8> = vec![
            0x01, 0x09, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x41, 0x00,
        ];
        let mut reader = src.as_slice();

        match Bloom::read(&mut reader) {
            Ok(Some(bloom)) => {
                assert!(bloom.has(&mut MurmurHash3IndexGenerator::new(
                    b"this".as_ref(),
                    bloom.size
                )));
                assert!(bloom.has(&mut MurmurHash3IndexGenerator::new(
                    b"that".as_ref(),
                    bloom.size
                )));
                assert!(!bloom.has(&mut MurmurHash3IndexGenerator::new(
                    b"other".as_ref(),
                    bloom.size
                )));
            }
            Ok(None) => panic!("Parsing failed"),
            Err(_) => panic!("Parsing failed"),
        };
        assert!(reader.is_empty());

        let short: Vec<u8> = vec![
            0x01, 0x09, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x41,
        ];
        assert!(Bloom::read(&mut short.as_slice()).is_err());

        let empty: Vec<u8> = Vec::new();
        let mut reader = empty.as_slice();
        match Bloom::read(&mut reader) {
            Ok(should_be_none) => assert!(should_be_none.is_none()),
            Err(_) => panic!("Parsing failed"),
        };
    }

    #[test]
    fn bloom_v3_unsupported() {
        let src: Vec<u8> = vec![0x03, 0x01, 0x00];
        assert!(Bloom::read(&mut src.as_slice()).is_err());
    }

    #[test]
    fn cascade_v1_murmur_from_file_bytes_test() {
        let v = include_bytes!("../test_data/test_v1_murmur_mlbf").to_vec();
        let cascade = Cascade::from_bytes(v)
            .expect("parsing Cascade should succeed")
            .expect("Cascade should be Some");
        // Key format is SHA256(issuer SPKI) + serial number
        #[rustfmt::skip]
        let key_for_revoked_cert_1 =
            [ 0x2e, 0xb2, 0xd5, 0xa8, 0x60, 0xfe, 0x50, 0xe9, 0xc2, 0x42, 0x36, 0x85, 0x52, 0x98,
              0x01, 0x50, 0xe4, 0x5d, 0xb5, 0x32, 0x1a, 0x5b, 0x00, 0x5e, 0x26, 0xd6, 0x76, 0x25,
              0x3a, 0x40, 0x9b, 0xf5,
              0x06, 0x2d, 0xf5, 0x68, 0xa0, 0x51, 0x31, 0x08, 0x20, 0xd7, 0xec, 0x43, 0x27, 0xe1,
              0xba, 0xfd ];
        assert!(cascade.has(&key_for_revoked_cert_1));
        #[rustfmt::skip]
        let key_for_revoked_cert_2 =
            [ 0xf1, 0x1c, 0x3d, 0xd0, 0x48, 0xf7, 0x4e, 0xdb, 0x7c, 0x45, 0x19, 0x2b, 0x83, 0xe5,
              0x98, 0x0d, 0x2f, 0x67, 0xec, 0x84, 0xb4, 0xdd, 0xb9, 0x39, 0x6e, 0x33, 0xff, 0x51,
              0x73, 0xed, 0x69, 0x8f,
              0x00, 0xd2, 0xe8, 0xf6, 0xaa, 0x80, 0x48, 0x1c, 0xd4 ];
        assert!(cascade.has(&key_for_revoked_cert_2));
        #[rustfmt::skip]
        let key_for_valid_cert =
            [ 0x99, 0xfc, 0x9d, 0x40, 0xf1, 0xad, 0xb1, 0x63, 0x65, 0x61, 0xa6, 0x1d, 0x68, 0x3d,
              0x9e, 0xa6, 0xb4, 0x60, 0xc5, 0x7d, 0x0c, 0x75, 0xea, 0x00, 0xc3, 0x41, 0xb9, 0xdf,
              0xb9, 0x0b, 0x5f, 0x39,
              0x0b, 0x77, 0x75, 0xf7, 0xaf, 0x9a, 0xe5, 0x42, 0x65, 0xc9, 0xcd, 0x32, 0x57, 0x10,
              0x77, 0x8e ];
        assert!(!cascade.has(&key_for_valid_cert));

        assert_eq!(cascade.approximate_size_of(), 15632);

        let v = include_bytes!("../test_data/test_v1_murmur_short_mlbf").to_vec();
        assert!(Cascade::from_bytes(v).is_err());
    }

    #[test]
    fn cascade_v2_sha256l32_from_file_bytes_test() {
        let v = include_bytes!("../test_data/test_v2_sha256l32_mlbf").to_vec();
        let cascade = Cascade::from_bytes(v)
            .expect("parsing Cascade should succeed")
            .expect("Cascade should be Some");

        assert!(cascade.salt.len() == 0);
        assert!(cascade.inverted == false);
        assert!(cascade.has(b"this") == true);
        assert!(cascade.has(b"that") == true);
        assert!(cascade.has(b"other") == false);
        assert_eq!(cascade.approximate_size_of(), 128314);
    }

    #[test]
    fn cascade_v2_sha256l32_with_salt_from_file_bytes_test() {
        let v = include_bytes!("../test_data/test_v2_sha256l32_salt_mlbf").to_vec();
        let cascade = Cascade::from_bytes(v)
            .expect("parsing Cascade should succeed")
            .expect("Cascade should be Some");

        assert!(cascade.salt == b"nacl".to_vec());
        assert!(cascade.inverted == false);
        assert!(cascade.has(b"this") == true);
        assert!(cascade.has(b"that") == true);
        assert!(cascade.has(b"other") == false);
        assert_eq!(cascade.approximate_size_of(), 128321);
    }

    #[test]
    fn cascade_v2_murmur_from_file_bytes_test() {
        let v = include_bytes!("../test_data/test_v2_murmur_mlbf").to_vec();
        let cascade = Cascade::from_bytes(v)
            .expect("parsing Cascade should succeed")
            .expect("Cascade should be Some");

        assert!(cascade.salt.len() == 0);
        assert!(cascade.inverted == false);
        assert!(cascade.has(b"this") == true);
        assert!(cascade.has(b"that") == true);
        assert!(cascade.has(b"other") == false);
        assert_eq!(cascade.approximate_size_of(), 127914);
    }

    #[test]
    fn cascade_v2_murmur_inverted_from_file_bytes_test() {
        let v = include_bytes!("../test_data/test_v2_murmur_inverted_mlbf").to_vec();
        let cascade = Cascade::from_bytes(v)
            .expect("parsing Cascade should succeed")
            .expect("Cascade should be Some");

        assert!(cascade.salt.len() == 0);
        assert!(cascade.inverted == true);
        assert!(cascade.has(b"this") == true);
        assert!(cascade.has(b"that") == true);
        assert!(cascade.has(b"other") == false);
        assert_eq!(cascade.approximate_size_of(), 128113);
    }

    #[test]
    fn cascade_v2_sha256l32_inverted_from_file_bytes_test() {
        let v = include_bytes!("../test_data/test_v2_sha256l32_inverted_mlbf").to_vec();
        let cascade = Cascade::from_bytes(v)
            .expect("parsing Cascade should succeed")
            .expect("Cascade should be Some");

        assert!(cascade.salt.len() == 0);
        assert!(cascade.inverted == true);
        assert!(cascade.has(b"this") == true);
        assert!(cascade.has(b"that") == true);
        assert!(cascade.has(b"other") == false);
        assert_eq!(cascade.approximate_size_of(), 128165);
    }

    #[test]
    fn cascade_v2_sha256ctr_from_file_bytes_test() {
        let v = include_bytes!("../test_data/test_v2_sha256ctr_salt_mlbf").to_vec();
        let cascade = Cascade::from_bytes(v)
            .expect("parsing Cascade should succeed")
            .expect("Cascade should be Some");

        assert!(cascade.salt == b"nacl".to_vec());
        assert!(cascade.inverted == false);
        assert!(cascade.has(b"this") == true);
        assert!(cascade.has(b"that") == true);
        assert!(cascade.has(b"other") == false);
        assert_eq!(cascade.approximate_size_of(), 128510);
    }

    #[test]
    fn cascade_empty() {
        let cascade = Cascade::from_bytes(Vec::new()).expect("parsing Cascade should succeed");
        assert!(cascade.is_none());
    }
}
