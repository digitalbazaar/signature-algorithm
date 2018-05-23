/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bs58 = require('bs58');
const chloride = require('chloride');

module.exports = class Ed25519 {

  async sign({plaintext, privateKeyBase58}) {
    const plaintextBuffer = Buffer.from(plaintext, 'utf8');
    const secretKey = bs58.decode(privateKeyBase58);
    return chloride.crypto_sign_detached(
      plaintextBuffer, secretKey).toString('base64');
  }

  async verify({plaintext, publicKeyBase58, signature}) {
    const plaintextBuffer = Buffer.from(plaintext, 'utf8');
    const signatureBuffer = Buffer.from(signature, 'base64');
    const publicKey = bs58.decode(publicKeyBase58);
    return chloride.crypto_sign_verify_detached(
      signatureBuffer, plaintextBuffer, publicKey);
  }

};
