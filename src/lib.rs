#![allow(dead_code)]
#![allow(unused_imports)]

extern crate bitvec;
extern crate digest;
extern crate murmurhash3;
extern crate rand;

use bitvec::*;
use murmurhash3::murmurhash3_x86_32;

use std::fs::File;
use std::io::prelude::*;
use std::io;
use std::iter::FromIterator;
use std::path::Path;
use std::str;

pub struct Bloom {
    level: u32,
    false_positive_rate: f32,
    n_hash_funcs: u32,
    size: usize,
    bitvec: BitVec<LittleEndian>,
}

impl Bloom {
    pub fn new(elements: u32, false_positive_rate: f32, level: u32) -> Bloom {

        let n_hash_funcs = ((1.0 / false_positive_rate).ln() / (2.0_f32).ln()).ceil() as u32;
        let hashes = n_hash_funcs as f32;
        let size = (1.0_f32 - (hashes * (elements as f32 + 0.5) / (1.0_f32 - false_positive_rate.powf(1.0 / hashes)).ln())).ceil() as usize;

        let bitvec: BitVec<LittleEndian> = bitvec![LittleEndian;0 ; size];

        Bloom {
            level: level,
            false_positive_rate: false_positive_rate,
            n_hash_funcs: n_hash_funcs,
            size: size,
            bitvec: bitvec,
        }
    }

    pub fn from_bytes(data: Vec<u8>, size: usize, false_positive_rate: f32, level: u32) -> Bloom {
        let bv: BitVec<LittleEndian> = data.into();

        Bloom {
            level: level,
            false_positive_rate: false_positive_rate,
            n_hash_funcs: ((1.0 / false_positive_rate).ln() / (2.0_f32).ln()).ceil() as u32,
            size: size,
            bitvec: bv,
        }
    }

    pub fn from_file<P: AsRef<Path>>(size: usize, false_positive_rate: f32, level: u32, mlbf_file: P) -> Bloom {
        let f = File::open(mlbf_file).unwrap();
        let mut v: Vec<u8> = vec![];
        let file_result: Result<Vec<u8>, _> = f.bytes().into_iter().collect();
        match file_result {
            Ok(data) => {
                for elem in data {
                    v.push(elem);
                }
                println!("Data is {:?}", v);
            },
            Err(err) => {
                println!("Something went wrong! {:?}", err);
            }
        }

        Bloom {
            level: level,
            false_positive_rate: false_positive_rate,
            n_hash_funcs: ((1.0 / false_positive_rate).ln() / (2.0_f32).ln()).ceil() as u32,
            size: size,
            bitvec: v.into(),
        }
    }

    fn hash(&self, n_fn: u32, key: &[u8]) -> usize {
        let hash_seed = (n_fn << 16) + self.level;
        println!("hash seed is {}, hash is {} size is {} len is {}", hash_seed, murmurhash3_x86_32(key, hash_seed) as usize, self.size, self.bitvec.len());
        let h = murmurhash3_x86_32(key, hash_seed) as usize % self.size;
        println!("h is {}", h);
        h
    }

    pub fn put(&mut self, item: &[u8]) {
        for i in 0..self.n_hash_funcs {
            let index = self.hash(i, item);
            self.bitvec.set(index, true);
        }
    }

    pub fn has(&self, item: &[u8]) -> bool {
        for i in 0..self.n_hash_funcs {
            println!("checking hash {}", i);
            if  self.bitvec.get(self.hash(i, item)) == false {
                println!("not present");
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
    depth: u32,
    error_rate: f32,
    oversize_factor: f32,
}

impl Cascade {
    pub fn new(capacity: usize, oversize_factor: f32, error_rate: f32) -> Cascade {
        return Cascade::new_layer(capacity, oversize_factor, error_rate, 0);
    }

    fn new_layer(capacity: usize, oversize_factor: f32, error_rate: f32, depth: u32) -> Cascade {
        Cascade {
            filter: Bloom::new((capacity as f32 * oversize_factor) as u32, 0.5, depth),
            child_layer: Option::None,
            depth: depth,
            error_rate: error_rate,
            oversize_factor: oversize_factor
        }
    }
    pub fn initialize(&mut self, entries: Vec<Vec<u8>>, exclusions: Vec<Vec<u8>>) {
        let mut false_positives = Vec::new();
        for entry in &entries {
            self.filter.put(entry);
        }

        for entry in exclusions {
            if self.filter.has(&entry) {
                false_positives.push(entry);
            }
        }

        if false_positives.len() > 0 {
            let mut child = Box::new(
                Cascade::new_layer(false_positives.len(), self.oversize_factor, self.error_rate, self.depth + 1));
            child.initialize(false_positives, entries);
            self.child_layer = Some(child);
        }
    }

    pub fn has(&self, entry: Vec<u8>) -> bool {
        if self.filter.has(&entry) {
            match self.child_layer {
                Some(ref child) => {
                    return ! child.has(entry);
                },
                None => {
                    return true;
                }
            }
        }
        return false;
    }

    pub fn check(&self, entries: Vec<Vec<u8>>, exclusions: Vec<Vec<u8>>) -> bool {
        for entry in entries {
            if ! self.has(entry.clone()) {
                return false;
            }
        }

        for entry in exclusions {
            if self.has(entry.clone()) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use Bloom;
    use Cascade;
    use rand::prelude::*;

    use bitvec::{BitVec, Bits};

    #[test]
    fn bloom_test_bloom_size() {
        let bloom = Bloom::new(1024, 0.01, 0);
        println!("{}", bloom.bitvec.len());
        assert!(bloom.bitvec.len() == 9829);
    }

    #[test]
    fn bloom_test_put() {
        let mut bloom = Bloom::new(1024, 0.01, 0);
        let key: &[u8] = b"foo";

        bloom.put(key);
    }

    #[test]
    fn bloom_test_has() {
        let mut bloom = Bloom::new(1024, 0.01, 0);
        let key: &[u8] = b"foo";

        bloom.put(key);
        assert!(bloom.has(key) == true);
        assert!(bloom.has(b"bar") == false);
    }

    #[test]
    fn bloom_test_from_bytes() {
        let src: Vec<u8> = vec![0x00, 0x18, 0x00];
        let mut bloom = Bloom::from_bytes(src, 17, 0.5, 0);
        println!("{:?}", bloom.bitvec);
        assert!(bloom.has(b"test") ==  true);
        assert!(bloom.has(b"that") ==  true);
        assert!(bloom.has(b"other") ==  false);

        bloom.put(b"other");
        assert!(bloom.has(b"other") ==  true);
    }

    #[test]
    fn bloom_test_from_file() {
        let bloom = Bloom::from_file(17, 0.5, 0, "test_bf");
        println!("{} {} {}", bloom.false_positive_rate, bloom.n_hash_funcs, bloom.size);
        
        assert!(bloom.has(b"test") == true);
        assert!(bloom.has(b"another test") == true);
        assert!(bloom.has(b"yet another test") == false);
    }

    #[test]
    fn filter_test() {
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

        let mut cascade = Cascade::new(500, 1.1, 0.5);
        cascade.initialize(foo.clone(), bar.clone());

        assert!(cascade.check(foo.clone(), bar.clone()) == true);
    }
}