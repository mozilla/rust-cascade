#![allow(dead_code)]
#![allow(unused_imports)]

extern crate sha2;
extern crate bit_vec;
extern crate byteorder;
extern crate rand;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use bit_vec::BitVec;
use sha2::{Sha256, Digest};

use std::str;

pub struct Bloom {
    bitvec: BitVec,
    k: u32,
    bits: usize
}

impl Bloom {
    pub fn new(size: usize, k: u32) -> Bloom {
        assert!(size > 0);

        let bits = size * 8usize;
        let bitvec = BitVec::from_elem(bits as usize, false);
        let k = k;

        Bloom {
            bitvec: bitvec,
            k: k,
            bits: bits,
        }
    }

    pub fn put<D: Digest + Default>(&mut self, item: &[u8]) {
        for i in 0..self.k {
            let mut hash = D::default();
            let mut buf = [0; 4];
            BigEndian::write_u32(&mut buf, i);
            hash.input(&buf);
            hash.input(item);
            self.bitvec.set(BigEndian::read_u32(&hash.result()) as usize % self.bits, true);
        }
    }

    pub fn has<D: Digest + Default>(&self, item: &[u8]) -> bool {
        for i in 0..self.k {
            let mut hash = Sha256::default();
            let mut buf = [0; 4];
            BigEndian::write_u32(&mut buf, i);
            hash.input(&buf);
            hash.input(item);
            if  self.bitvec.get(BigEndian::read_u32(&hash.result()) as usize % self.bits).unwrap() == false {
                return false;
            }
        }

        return true
    }

    pub fn clear(&mut self) {
        self.bitvec.clear()
    }
}

pub struct Cascade {
    filter: Bloom,
    child_layer: Option<Box<Cascade>>,
    depth: usize
}

impl Cascade {
    pub fn new(capacity: usize) -> Cascade {
        return Cascade::new_layer(capacity, 0);
    }

    fn new_layer(capacity: usize, depth: usize) -> Cascade {
        Cascade {
            // TODO: MDG calculate k based on error rate - hardcoded for groovecoder's example
            filter: Bloom::new(capacity, 2),
            child_layer: Option::None,
            depth: depth
        }
    }
    pub fn initialize<D: Digest + Default>(&mut self, entries: Vec<Vec<u8>>, exclusions: Vec<Vec<u8>>) {
        let mut false_positives = Vec::new();
        for entry in &entries {
            self.filter.put::<D>(entry);
        }

        for entry in exclusions {
            if self.filter.has::<D>(&entry) {
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
            let mut child = Box::new(Cascade::new_layer(mangled_false_positives.len(), self.depth + 1));
            child.initialize::<D>(mangled_false_positives, mangled_entries);
            self.child_layer = Some(child);
        }
    }

    pub fn has<D: Digest + Default>(&self, entry: Vec<u8>) -> bool {
        if self.filter.has::<D>(&entry) {
            let mut mangled_entry = entry.to_vec();
            if self.depth > 0 {
                mangled_entry.push(65);
            }
            match self.child_layer {
                Some(ref child) => {
                    return ! child.has::<D>(mangled_entry);
                },
                None => {
                    return true;
                }
            }
        }
        return false;
    }

    pub fn check<D:Digest + Default>(&self, entries: Vec<Vec<u8>>, exclusions: Vec<Vec<u8>>) -> bool {
        for entry in entries {
            if ! self.has::<D>(entry.clone()) {
                return false;
            }
        }

        for entry in exclusions {
            if self.has::<D>(entry.clone()) {
                return false;
            }
        }

        true
    }
}

#[test]
fn bloom_test_bloom_size() {
    let bloom = Bloom::new(1024, 2);
    assert!(bloom.bitvec.len() == 8192);
}

#[test]
fn bloom_test_put() {
    let mut bloom = Bloom::new(1024, 2);
    let key: &[u8] = b"foo";

    bloom.put::<Sha256>(key);;
}

#[test]
fn bloom_test_has() {
    let mut bloom = Bloom::new(1024, 2);
    let key: &[u8] = b"foo";

    bloom.put::<Sha256>(key);
    assert!(bloom.has::<Sha256>(key) == true);
    assert!(bloom.has::<Sha256>(b"bar") == false);
}

#[test]
fn filter_test() {
    use rand::prelude::*;

    // thread_rng is often the most convenient source of randomness:
    let mut rng = thread_rng();

    // create some entries and exclusions
    let mut foo : Vec<Vec<u8>> = Vec::new();
    let mut bar : Vec<Vec<u8>> = Vec::new();

    for i in 0..500 {
        let s = format!("{}", i);
        let bytes = s.into_bytes();
        foo.push(bytes);
    }

    for _ in 0..100 {
        let idx = rng.gen_range(0, foo.len());
        bar.push(foo.swap_remove(idx));
    }

    let mut cascade = Cascade::new(500);
    cascade.initialize::<Sha256>(foo.clone(), bar.clone());

    assert!(cascade.check::<Sha256>(foo.clone(), bar.clone()) == true);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
