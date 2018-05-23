/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const crypto = require('crypto');

module.exports = class Hmac {

  async sign({hashType, plaintext, sharedKey}) {
    const signer = crypto.createHmac(hashType.toUpperCase(), sharedKey);
    signer.update(plaintext);
    return signer.digest('base64');
  }

  async verify({hashType, plaintext, sharedKey, signature}) {
    const verifier = crypto.createHmac(hashType.toUpperCase(), sharedKey);
    verifier.update(plaintext);
    return (signature === verifier.digest('base64'));
  }

};
