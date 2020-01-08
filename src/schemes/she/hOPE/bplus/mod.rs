#![feature(nll)]

use mongodb::coll::Collection;
use paillier::*;
use paillier::integral::*;
use bson::*;
use mongodb::oid::ObjectId;
use schemes::she::hOPE::*;
use mongodb::coll::results::InsertOneResult;
use mongodb::{Bson, bson, doc, Client, ThreadedClient};
use serde_cbor::ser::to_vec_packed;
use serde_cbor::from_slice;
use std::path::Path;
use std::fs::File;
use std::error::Error;
use std::io::{Write, Read};
use utils::file::read_raw;
use base64::{encode, decode};
const TREE_BEGIN: &'static str = "-----BEGIN TREE-----\n";
const TREE_END: &'static str = "\n-----END TREE-----";
use std::marker::PhantomData;

pub mod tree;
use self::tree::Node;
use self::tree::node::Leaf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Tree {
    pub _id: ObjectId,
    pub _degree: usize,
    pub _root: Option<Node>,
}

impl Tree {
    pub fn new(degree: usize) -> Tree {
        Tree {
            _id: ObjectId::new().unwrap(),
            _degree: degree,
            _root: None,
        }
    }

    pub fn search(&self, key: Leaf) -> Option<&Node> {
        match self._root {
            None => None,
            Some(ref root) => root.search(key),
        }
    }

    pub fn code(&self, _key: ObjectId) -> Option<u64> {
        match self._root {
            None => None,
            Some(ref root) => root.code(0, _key),
        }
    }

    pub fn update_apl(&self, _coll: &Collection) {
        match &self._root {
            None => {}
            Some(_r) => _r.update_apl(0, _coll),
        }
    }

    pub fn insert(&mut self, _key: Leaf) {
        match self._root {
            None => {
                let mut node = Node::new(self._degree, true);
                node.insert_key(_key);
                self._root = Some(node);
            }
            Some(ref mut root) => {
                // Create a new root if filled
                if root.is_full() {
                    // rendundant code here to get around rust's ownership checks
                    let mut left = Node::new(root._degree, true);
                    let mut right = Node::new(root._degree, true);
                    let mut index = 0;
                    while index < root.capacity() {
                        let k = root.remove_key(_key.clone());
                        if index < self._degree - 1 {
                            left.insert_key(k.clone());
                        } else if index > self._degree - 1 {
                            right.insert_key(k.clone());
                        } else {
                            root._num_cts += 1;
                            root._cts.push(k);
                        }
                        index += 1;
                    }
                    root._children.push(left);
                    root._children.push(right);
                    root._is_leaf = false;
                }

                let mut x = root;
                loop {
                    if x._is_leaf {
                        break;
                    }

                    let mut i = 0;
                    while i < x._num_cts {
                        //&& _elem._c > x._cts[i] {
                        i += 1;
                    }

                    if x._children[i].is_full() {
                        // Split the node if it's full
                        let child = x._children.remove(i);
                        let (k, lnode, rnode) = child.split();
                        let inserted_index = x.insert_key(k);
                        x._children.insert(inserted_index, lnode);
                        x._children.insert(inserted_index + 1, rnode);
                    } else {
                        x = &mut x._children[i];
                    }
                }
                // Insert key
                x.insert_key(_key);
            }
        }
    }

    /*
    pub fn serialize_mongo(
        &self,
        collection: &Collection,
    ) -> Result<InsertOneResult, mongodb::Error> {
        let serialized_tree = bson::to_bson(&self);
        match serialized_tree {
            Ok(res) => {
                if let bson::Bson::Document(doc) = res {
                    collection.insert_one(doc, None)
                } else {
                    panic!("Error bsoning Tree");
                }
            }
            Err(e) => {
                println!("Error bsoning Tree");
                return Result::Err(mongodb::Error::EncoderError(e));
            }
        }
    }

    pub fn deserialize_mongo<u64>(&mut self, collection: &Collection, _id: ObjectId) {
        // Read the document from a MongoDB collection
        let serialized_tree = collection
            .find_one(Some(doc! { "_id":  _id }), None)
            .expect("Document was not found");
        match serialized_tree {
            Some(tree) => {
                let _final = bson::from_bson::<Tree>(bson::Bson::Document(tree)).unwrap();
                *self = _final;
            }
            None => {
                panic!("Error: could not find Object");
            }
        }
    }

    pub fn serialize_file(&self, _path: &Path) -> bool {
        let serialized = to_vec_packed(&self).unwrap();
        write_file(
            _path,
            [TREE_BEGIN, &encode(&serialized).as_str(), TREE_END].concat(),
        )
    }

    pub fn deserialize_file(&mut self, _path: &Path) {
        *self = from_slice(&decode(&read_raw(&read_file(_path))).unwrap()).unwrap();
    }
    */
}

impl std::fmt::Display for Tree {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "@tree:{} (degree:{}, root:{:?})",
            self._id,
            self._degree,
            self._root
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Tree;

    #[test]
    fn it_has_ordered_inserts() {
        let mut btree = Tree::new(3);
        btree.insert(2);
        btree.insert(1);
        btree.insert(3);
        assert_eq!(btree._root.unwrap()._cts, vec![1, 2, 3]);
    }

    #[test]
    fn it_splits_the_root() {
        let mut btree = Tree::new(3);
        btree.insert(1);
        btree.insert(2);
        btree.insert(3);
        btree.insert(4);
        btree.insert(5);
        btree.insert(6);
        let root = &btree._root.unwrap();
        assert_eq!(root._cts, vec![3]);
        assert_eq!(root._children[0]._cts, vec![1, 2]);
        assert_eq!(root._children[1]._cts, vec![4, 5, 6]);
    }

    #[test]
    fn it_splits_the_child() {
        let mut btree = Tree::new(3);
        btree.insert(1);
        btree.insert(2);
        btree.insert(3);
        btree.insert(4);
        btree.insert(5);
        btree.insert(6);
        btree.insert(7);
        btree.insert(8);
        btree.insert(9);
        let root = &btree._root.unwrap();
        assert_eq!(root._cts, vec![3, 6]);
        assert_eq!(root._children[0]._cts, vec![1, 2]);
        assert_eq!(root._children[1]._cts, vec![4, 5]);
        assert_eq!(root._children[2]._cts, vec![7, 8, 9]);
    }
}
