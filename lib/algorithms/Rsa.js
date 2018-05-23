/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const crypto = require('crypto');

module.exports = class Rsa {

  async sign({hashType, plaintext, privateKeyPem}) {
    const signer = crypto.createSign(hashType.toUpperCase());
    signer.update(plaintext);
    return signer.sign(privateKeyPem, 'base64');
  }

  async verify({hashType, plaintext, publicKeyPem, signature}) {
    const verifier = crypto.createVerify(hashType.toUpperCase());
    verifier.update(plaintext);
    return verifier.verify(publicKeyPem, signature, 'base64');
  }

};
