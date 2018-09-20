#![allow(dead_code)]
#![allow(unused_imports)]

extern crate bit_vec;
extern crate byteorder;
extern crate digest;
extern crate rand;
extern crate sha2;

use bit_vec::BitVec;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};

use std::str;

pub trait BloomHasher {
    fn bloom_input(&mut self, data: &[u8]);
    fn bloom_result(&mut self) -> Vec<u8>;
}

pub trait HasherMaker {
    fn make_hasher(&self) -> Box<BloomHasher>;
}

pub struct Bloom<'a> {
    bitvec: BitVec,
    k: u32,
    bits: usize,
    hasher_maker: &'a HasherMaker,
}

impl<'a> Bloom<'a> {
    pub fn new(size: usize, k: u32, hasher_maker: &'a HasherMaker) -> Bloom {
        assert!(size > 0);

        let bits = size * 8usize;
        let bitvec = BitVec::from_elem(bits as usize, false);
        let k = k;

        Bloom {
            bitvec: bitvec,
            k: k,
            bits: bits,
            hasher_maker: hasher_maker,
        }
    }

    pub fn put(&mut self, item: &[u8]) {
        for i in 0..self.k {
            let mut hash = self.hasher_maker.make_hasher();
            let mut buf = [0; 4];
            BigEndian::write_u32(&mut buf, i);
            hash.bloom_input(&buf);
            hash.bloom_input(item);
            self.bitvec.set(
                BigEndian::read_u32(&hash.bloom_result()) as usize % self.bits,
                true,
            );
        }
    }

    pub fn has(&self, item: &[u8]) -> bool {
        for i in 0..self.k {
            let mut hash = self.hasher_maker.make_hasher();
            let mut buf = [0; 4];
            BigEndian::write_u32(&mut buf, i);
            hash.bloom_input(&buf);
            hash.bloom_input(item);
            if self
                .bitvec
                .get(BigEndian::read_u32(&hash.bloom_result()) as usize % self.bits)
                .unwrap()
                == false
            {
                return false;
            }
        }

        return true;
    }

    pub fn clear(&mut self) {
        self.bitvec.clear()
    }
}

pub struct Cascade<'a> {
    filter: Bloom<'a>,
    child_layer: Option<Box<Cascade<'a>>>,
    depth: usize,
    hasher_maker: &'a HasherMaker,
}

impl<'a> Cascade<'a> {
    pub fn new(capacity: usize, hasher_maker: &'a HasherMaker) -> Cascade<'a> {
        return Cascade::new_layer(capacity, 0, hasher_maker);
    }

    fn new_layer(capacity: usize, depth: usize, hasher_maker: &'a HasherMaker) -> Cascade<'a> {
        Cascade {
            // TODO: MDG calculate k based on error rate - hardcoded for groovecoder's example
            filter: Bloom::new(capacity, 2, hasher_maker),
            child_layer: Option::None,
            depth: depth,
            hasher_maker: hasher_maker,
        }
    }
    pub fn initialize(&mut self, entries: &Vec<Vec<u8>>, exclusions: &Vec<Vec<u8>>) {
        let mut false_positives = Vec::new();
        for entry in entries {
            self.filter.put(entry);
        }

        for entry in exclusions {
            if self.filter.has(entry) {
                false_positives.push(entry);
            }
        }

        if false_positives.len() > 0 {
            let mut mangled_false_positives = Vec::new();
            let mut mangled_entries = Vec::new();
            println!("New layer for {} false positives", false_positives.len());

            for entry in false_positives {
                let mut v = entry.to_vec();
                if self.depth > 0 {
                    v.push(65);
                }
                mangled_false_positives.push(v);
            }

            for entry in entries {
                let mut v = entry.to_vec();
                if self.depth > 0 {
                    v.push(65);
                }
                mangled_entries.push(v);
            }
            let mut child = Box::new(Cascade::new_layer(
                mangled_false_positives.len(),
                self.depth + 1,
                self.hasher_maker,
            ));
            child.initialize(&mangled_false_positives, &mangled_entries);
            self.child_layer = Some(child);
        }
    }

    pub fn has(&self, entry: &Vec<u8>) -> bool {
        if self.filter.has(entry) {
            let mut mangled_entry = entry.to_vec();
            if self.depth > 0 {
                mangled_entry.push(65);
            }
            match self.child_layer {
                Some(ref child) => {
                    return !child.has(&mangled_entry);
                }
                None => {
                    return true;
                }
            }
        }
        return false;
    }

    pub fn check(&self, entries: &Vec<Vec<u8>>, exclusions: &Vec<Vec<u8>>) -> bool {
        for entry in entries {
            if !self.has(entry) {
                return false;
            }
        }

        for entry in exclusions {
            if self.has(entry) {
                return false;
            }
        }

        true
    }
}

// construct a BloomHasher and HasherMaker for tests
use sha2::{Digest, Sha256};

// Implement the BloomHasher trait for sha2::Sha256 - we could also do this for the hash types used by
// the standard collections
impl BloomHasher for Sha256 {
    fn bloom_input(&mut self, data: &[u8]) {
        self.input(data)
    }

    fn bloom_result(&mut self) -> Vec<u8> {
        self.clone().result().to_vec()
    }
}

struct Sha256Maker {}
impl HasherMaker for Sha256Maker {
    fn make_hasher(&self) -> Box<BloomHasher> {
        Box::new(Sha256::default())
    }
}

#[test]
fn bloom_test_bloom_size() {
    let maker = Sha256Maker {};
    let bloom = Bloom::new(1024, 2, &maker);
    assert!(bloom.bitvec.len() == 8192);
}

#[test]
fn bloom_test_put() {
    let maker = Sha256Maker {};
    let mut bloom = Bloom::new(1024, 2, &maker);
    let key: &[u8] = b"foo";

    bloom.put(key);
}

#[test]
fn bloom_test_has() {
    let maker = Sha256Maker {};
    let mut bloom = Bloom::new(1024, 2, &maker);
    let key: &[u8] = b"foo";

    bloom.put(key);
    assert!(bloom.has(key) == true);
    assert!(bloom.has(b"bar") == false);
}

#[test]
fn filter_test() {
    use rand::prelude::*;

    // thread_rng is often the most convenient source of randomness:
    let mut rng = thread_rng();

    // create some entries and exclusions
    let mut foo: Vec<Vec<u8>> = Vec::new();
    let mut bar: Vec<Vec<u8>> = Vec::new();

    for i in 0..500 {
        let s = format!("{}", i);
        let bytes = s.into_bytes();
        foo.push(bytes);
    }

    for _ in 0..100 {
        let idx = rng.gen_range(0, foo.len());
        bar.push(foo.swap_remove(idx));
    }

    let maker = Sha256Maker {};
    let mut cascade = Cascade::new(500, &maker);
    cascade.initialize(&foo, &bar);

    assert!(cascade.check(&foo, &bar) == true);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
