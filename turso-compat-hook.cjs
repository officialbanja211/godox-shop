const Module = require('node:module');
const path = require('node:path');
const originalLoad = Module._load;
const compat = require(path.join(__dirname, 'turso-sync.cjs'));
Module._load = function(request, parent, isMain) {
  if (request === 'node:sqlite') return compat;
  return originalLoad.call(this, request, parent, isMain);
};
