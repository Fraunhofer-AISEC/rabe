var ffi = require('ffi');

var lib = ffi.Library('../target/release/librabe', {
  'bsw_context_create': ['void', []]
});

lib.bsw_context_create();

console.log("done!");
