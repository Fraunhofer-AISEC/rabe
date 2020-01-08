use paillier::*;
use mongodb::oid::ObjectId;
use mongodb::{Bson, bson, doc, Client, ThreadedClient};
use mongodb::coll::Collection;
use std::ops::Shl;
use std::cmp::Ordering;
use std::marker::PhantomData;

pub mod node;
use self::node::Leaf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Node {
    pub _degree: usize,
    pub _num_cts: usize,
    pub _is_leaf: bool,
    pub _children: Vec<Node>,
    pub _cts: Vec<Leaf>,
}

impl Node {
    pub fn new(_degree: usize, _is_leaf: bool) -> Node {
        Node {
            _degree: _degree,
            _num_cts: 0,
            _is_leaf: _is_leaf,
            _children: Vec::with_capacity(_degree - 1),
            _cts: Vec::with_capacity(_degree),
        }
    }

    pub fn capacity(&self) -> usize {
        self._degree
    }

    pub fn insert_key(&mut self, _key: Leaf) -> usize {
        let mut i = 0;
        while i < self._num_cts {
            //&& super::super::ask_client(key > self._cts[i]) {
            i += 1;
        }
        self._num_cts += 1;
        self._cts.insert(i, _key);
        i
    }

    pub fn remove_key(&mut self, _key: Leaf) -> Leaf {
        let mut i = 0;
        while i < self._num_cts && self._cts[i] != _key {
            i += 1;
        }
        self._num_cts -= 1;
        return self._cts.remove(i);
    }


    pub fn is_full(&self) -> bool {
        self._cts.len() == self._degree
    }

    pub fn split(self) -> (Leaf, Node, Node) {
        let _key: Leaf = self._cts[self._degree - 1].clone();
        let mut left = Node::new(self._degree, self._is_leaf);
        let mut right = Node::new(self._degree, self._is_leaf);

        for (index, k) in self._cts.iter().enumerate() {
            if index < self._degree - 1 {
                left.insert_key(k.clone());
            } else if index > self._degree - 1 {
                right.insert_key(k.clone());
            }
        }
        let mut index = 0;
        for child in self._children {
            if index < self._degree {
                left._children.push(child);
            } else {
                right._children.push(child);
            }
            index += 1;
        }
        return (_key, left, right);
    }

    pub fn search(&self, _key: Leaf) -> Option<&Node> {
        // Find the first key greater than or equal to k
        let mut i = 0;
        while i < self._num_cts {
            //&& super::super::ask_client(key > self._cts[i]) {
            // If key is on this node, return the node
            if self._cts[i] == _key {
                return Some(self);
            }
            i += 1;
        }
        if self._is_leaf == true {
            return None;
        }
        return self._children[i].search(_key);
    }

    pub fn code(&self, _code: u64, _key: ObjectId) -> Option<u64> {
        // Find the first key greater than or equal to k
        let mut i = 0;
        while i < self._num_cts {
            //&& super::super::ask_client(key > self._cts[i]) {

            // If key is on this node, return the node
            if self._cts[i]._id == _key {
                let _code = (_code + u64::from(i as u32)).shl(self.capacity());
                Some(_code);
            }
            i += 1;
        }
        if self._is_leaf == true {
            return None;
        }
        return self._children[i].code((_code + u64::from(i as u32)).shl(self.capacity()), _key);
    }

    pub fn update_apl(&self, _code: u64, _coll: &Collection) {
        let mut i = 0;
        if self._num_cts == 0 {
            while i < self._children.len() {
                let _current_code = (_code + u64::from(i as u32)).shl(self.capacity());
                self._children[i].update_apl(_current_code, _coll);
                i += 1;
            }
        } else {
            i = 0;
            while i < self._num_cts {
                _coll
	                .update_one(
	                    doc!{"_id" => self._cts[i]._id.clone()},
	                    doc!{"$set" => {"_o" => (_code + u64::from(i as u32)).shl(self.capacity())}},
	                        None,
                    )
                    .unwrap();
            }
            i += 1;
        }
    }
}

impl std::fmt::Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "@node[_degree:{:?}, _num_cts:{:?}, _is_leaf:{:?}, _children:{:?}, _cts:{:?}]",
            self._degree,
            self._num_cts,
            self._is_leaf,
            self._children,
            self._cts
        )
    }
}
