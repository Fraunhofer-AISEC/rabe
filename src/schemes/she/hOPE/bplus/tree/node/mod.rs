use paillier::*;
use mongodb::oid::ObjectId;
use mongodb::{Bson, bson, doc, Client, ThreadedClient};
use mongodb::coll::Collection;
use std::cmp::Ordering;
use std::marker::PhantomData;

#[derive(Serialize, Deserialize, Debug)]
pub struct Leaf {
    pub _id: ObjectId,
    pub _c: EncodedCiphertext<u64>,
    pub _o: u64,
}

impl Leaf {
    pub fn new(_id: ObjectId, _c: EncodedCiphertext<u64>) -> Leaf {
        Leaf {
            _id: _id,
            _c: _c,
            _o: 0u64,
        }
    }
}

impl Ord for Leaf {
    fn cmp(&self, other: &Self) -> Ordering {
        self._o.cmp(&other._o)
    }
}

impl PartialOrd for Leaf {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Leaf {
    fn eq(&self, other: &Self) -> bool {
        self._o == other._o
    }
}


impl Clone for Leaf {
    fn clone(&self) -> Leaf {
        Leaf {
            _id: self._id.clone(),
            _c: self._c.clone(),
            _o: self._o.clone(),
        }
    }
}

impl Eq for Leaf {}

impl std::fmt::Display for Leaf {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "@leaf[id:{:?}, _o:{:?}, _c:{:?}]",
            self._id,
            self._o,
            self._c,
        )
    }
}
