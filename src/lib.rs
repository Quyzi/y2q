use core::range::RangeInclusive;
use std::ops::Deref;

use bytes::Bytes;

pub struct Object(Bytes);

impl Deref for Object {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Metadata {
    pub created: u64,
    pub modified: u64,
    pub size: u64,
    pub checksum_md5: u64,
    pub checksum_sha256: u64,
}

pub enum Error {
    InvalidBucket {
        bucket: String,
    },

    InvalidKey {
        key: String,
    },

    NotFound {
        bucket: String,
        key: String
    },

    InternalError {
        bucket: String,
        key: String,
        operation: String, 
        message: String, 
    }
}

pub trait Storage {
    /// Get an object out of the storage backend by bucket and key
    fn get(bucket: &str, key: &str) -> Result<Object, Error>;

    /// Get a range of bytes of an object
    fn get_range(bucket: &str, key: &str, range: RangeInclusive<u64>) -> Result<Bytes, Error>;
    
    /// Store an object. Returns true if overwriting an existing object with the same bucket and key. 
    fn put(bucket: &str, key: &str, payload: Object) -> Result<bool, Error>;
    
    /// Delete an object. Returns the deleted object.
    fn delete(bucket: &str, key: &str) -> Result<Object, Error>;
    
    /// Describe an object, returning its metadata. 
    fn describe(bucket: &str, key: &str) -> Result<Metadata, Error>;
}
