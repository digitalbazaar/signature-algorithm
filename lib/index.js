/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const Algorithms = require('./Algorithms');
const algorithms = new Algorithms();
const {callbackify} = require('util');
const Ed25519 = require('./algorithms/Ed25519');
const Hmac = require('./algorithms/Hmac');
const Rsa = require('./algorithms/Rsa');

// TODO: split this module up into a main API with no signatures installed
// and plugins that can be installed to support various signature algorithms

const api = {};
module.exports = api;

api.sign = maybeCallbackify(async ({
  algorithm, hashType, plaintext, privateKeyBase58, privateKeyPem, sharedKey
}) => api.use(algorithm).sign(
  {hashType, plaintext, privateKeyBase58, privateKeyPem, sharedKey}));

api.verify = maybeCallbackify(async ({
  algorithm, hashType, plaintext, publicKeyBase58, publicKeyPem,
  sharedKey, signature
}) => api.use(algorithm).verify({
  hashType, plaintext, publicKeyBase58, publicKeyPem, sharedKey, signature}));

function maybeCallbackify(original) {
  const callbackified = callbackify(original);
  return function(...args) {
    const fn = args[args.length - 1];
    if(typeof fn === 'function') {
      return callbackified.apply(null, args);
    }
    return original.apply(null, args);
  };
}

api.use = (name, algorithm) => algorithms.use(name, algorithm);

api.use('ed25519', new Ed25519());
api.use('hmac', new Hmac());
api.use('rsa', new Rsa());
