/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class Algorithms {
  constructor() {
    this._algorithms = {};
  }

  /**
   * Allows algorithms to be set or retrieved.
   *
   * @param name the name of the algorithm to use (e.g. rsa, hmac, ed25519)
   * @param [algorithm] the api to set for the algorithm, only present for
   *          setter, omit for getter.
   *
   * @return the API for `name` if not using this method as a setter, otherwise
   *           undefined.
   */
  use(name, algorithm) {
    // setter mode
    if(algorithm) {
      this._algorithms[name] = algorithm;
      return;
    }
    // getter mode:
    const algo = this._algorithms[name];
    if(algo === undefined) {
      throw new Error(`Unknown algorithm '${name}'.`);
    }
    return algo;
  }
};
