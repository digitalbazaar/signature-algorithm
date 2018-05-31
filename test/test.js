/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
const mockData = require('./mock-data');
const should = chai.should();

// const {expect} = chai;
const hsc = require('..');

describe('signature-algorithms', () => {

  describe('Promise API', () => {

    describe('sign API', () => {
      it('returns an error on an unknown algorithm', async () => {
        let result;
        let err;
        try {
          result = await hsc.sign({algorithm: 'abc'});
        } catch(e) {
          err = e;
        }
        should.not.exist(result);
        should.exist(err);
        err.message.should.equal('Unknown algorithm \'abc\'.');
      });

      describe('Ed25519', () => {
        it('creates a signature', () => {
          const plaintext = 'abc123';
          const {privateKeyBase58} = mockData.ed25519KeyPair;
          return hsc.sign({algorithm: 'ed25519', plaintext, privateKeyBase58})
            .then(signature => {
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'q/tQqxBlhzSP+XTte7uYaaCyJXJvg8svdjV47E2rBrVI1fBIOAeKj5Jm7qB' +
                'kH0IL8CvKRboqHBCoITDrsT9DAQ==');
            });
        });
      });

      describe('HMAC', () => {
        it('creates a signature using sha256', () => {
          const plaintext = 'abc123';
          const sharedKey = 'secretKey';
          return hsc.sign(
            {algorithm: 'hmac', hashType: 'sha256', plaintext, sharedKey})
            .then(signature => {
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'FNAWrxLnd6YsyXGPvhZnoXvKERY+jzQ1TF2ucMmdEIA=');
            });
        });
        it('creates a signature using sha512', () => {
          const plaintext = 'abc123';
          const sharedKey = 'secretKey';
          return hsc.sign(
            {algorithm: 'hmac', hashType: 'sha512', plaintext, sharedKey})
            .then(signature => {
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'mnTTyVH8P4ymXE3dl6DRAZFSic2ElBvLH5yqjJziFZSm1B3ZI' +
                'V3r7KwKpbWasAZxPXjqZy8DnY8v++0+bVIQBQ==');
            });
        });
        it('returns an error on invalid `hashType`', async () => {
          const plaintext = 'abc123';
          const sharedKey = 'secretKey';
          let result;
          let err;
          try {
            result = await hsc.sign(
              {algorithm: 'hmac', hashType: 'unknown', plaintext, sharedKey});

          } catch(e) {
            err = e;
          }
          should.not.exist(result);
          should.exist(err);
          err.message.should.contain('Unknown message digest');
        });
      });

      describe('RSA', () => {
        it('creates a signature using sha256', () => {
          const plaintext = 'abc123';
          const {privateKeyPem} = mockData.rsa2048KeyPair;
          return hsc.sign(
            {algorithm: 'rsa', hashType: 'sha256', plaintext, privateKeyPem})
            .then(signature => {
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'oHLS9K71TPOUQ7IG7Hdeq7jSmnoS6C2xyPvtlo56bizif1w/z' +
                '62OEIiFpz2Oe784vDcWEI7/x5fYdB/uqIfdbkaquI78OZpVCl' +
                'FVteTOmOw6EhQJ66hJLkml+8LnMSs0Y6v3Cd+wLsCfWpa/2PU' +
                'ZcLjv1AOV3vhYhTdTXl4ufCwdWuSpPtA8L4LC7rak5mb/wmNCt' +
                'iZ/Ol2/lhpwP6lPX+1UkH3EWFBTGDPnquk340TWRVXevrHDVSG' +
                'F6Z8CS0TEmx1eX2+R8PJlRJ/ExA0vWEAc7O7Y7KctKKU+wWobL' +
                'qftt9LGnThtWDKOHJlmQjt6k7S2WzvV5iIhVfLXee1tfw==');
            });
        });
        it('creates a signature using sha512', () => {
          const plaintext = 'abc123';
          const {privateKeyPem} = mockData.rsa2048KeyPair;
          return hsc.sign(
            {algorithm: 'rsa', hashType: 'sha512', plaintext, privateKeyPem})
            .then(signature => {
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'Pkfeqzy5qKRROV6BmakMFpK+JFcbxRrHHbB9qHDiUMmM+sj66kSLMml/+' +
                'T1lmCnWqXciupF1eG429j3Ulj706Ppog7AcvMSkSsKBy5WZ0yZCYqu6Fv' +
                'FOdpWiRqNvNAA+7YB2WdSutt8ABxP23Fk0+mROq8bZ4UHw5WOS69LyokJ' +
                'JwYt00HC8eK3MOuSdcjBrDAHh5EeoTN4hHTMlkpmY2SHYtjbyt9dIK2xX' +
                'VYvWyUIdrYHpBs4gyFV0aHd/q1tNfzpL0m1/oSRKbHfx3RURqArBdeJi0' +
                'N5CldSvFAMy4gT1elcsc5F3BRrEp1GkmzuwI+R80xWCVLi4Mbqn0xsADQ==');
            });
        });
        it('returns an error on invalid `hashType`', async () => {
          const plaintext = 'abc123';
          const {privateKeyPem} = mockData.rsa2048KeyPair;
          let result;
          let err;
          try {
            result = await hsc.sign({
              algorithm: 'rsa', hashType: 'unknown', plaintext, privateKeyPem
            });
          } catch(e) {
            err = e;
          }
          should.not.exist(result);
          should.exist(err);
          err.message.should.contain('Unknown message digest');
        });
      });
    });

    describe('verify API', () => {
      it('returns an error on an unknown algorithm', async () => {
        let result;
        let err;
        try {
          result = await hsc.verify({algorithm: 'abc'});
        } catch(e) {
          err = e;
        }
        should.not.exist(result);
        should.exist(err);
        err.message.should.equal('Unknown algorithm \'abc\'.');
      });

      describe('Ed25519', () => {
        it('verifies a signature', () => {
          const plaintext = 'abc123';
          const {publicKeyBase58} = mockData.ed25519KeyPair;
          return hsc.verify({
            algorithm: 'ed25519', plaintext, publicKeyBase58,
            signature: 'q/tQqxBlhzSP+XTte7uYaaCyJXJvg8svdjV47E2rBrVI1fBIOAeK' +
              'j5Jm7qBkH0IL8CvKRboqHBCoITDrsT9DAQ=='
          }).then(verified => {
            should.exist(verified);
            verified.should.be.a('boolean');
            verified.should.be.true;
          });
        });
      });

      describe('HMAC', () => {
        it('verifies a signature', () => {
          const plaintext = 'abc123';
          const sharedKey = 'secretKey';
          return hsc.verify({
            algorithm: 'hmac', hashType: 'sha512', plaintext, sharedKey,
            signature: 'mnTTyVH8P4ymXE3dl6DRAZFSic2ElBvLH5yqjJziFZSm1B3ZI' +
            'V3r7KwKpbWasAZxPXjqZy8DnY8v++0+bVIQBQ=='})
            .then(verified => {
              should.exist(verified);
              verified.should.be.a('boolean');
              verified.should.be.true;
            });
        });
      });

      describe('RSA', () => {
        it('verifies a signature', () => {
          const plaintext = 'abc123';
          const {publicKeyPem} = mockData.rsa2048KeyPair;
          return hsc.verify({
            algorithm: 'rsa', hashType: 'sha512', plaintext, publicKeyPem,
            signature:
              'Pkfeqzy5qKRROV6BmakMFpK+JFcbxRrHHbB9qHDiUMmM+sj66kSLMml/+' +
              'T1lmCnWqXciupF1eG429j3Ulj706Ppog7AcvMSkSsKBy5WZ0yZCYqu6Fv' +
              'FOdpWiRqNvNAA+7YB2WdSutt8ABxP23Fk0+mROq8bZ4UHw5WOS69LyokJ' +
              'JwYt00HC8eK3MOuSdcjBrDAHh5EeoTN4hHTMlkpmY2SHYtjbyt9dIK2xX' +
              'VYvWyUIdrYHpBs4gyFV0aHd/q1tNfzpL0m1/oSRKbHfx3RURqArBdeJi0' +
              'N5CldSvFAMy4gT1elcsc5F3BRrEp1GkmzuwI+R80xWCVLi4Mbqn0xsADQ=='
          }).then(verified => {
            should.exist(verified);
            verified.should.be.a('boolean');
            verified.should.be.true;
          });
        });
      });
    });
  });

  describe('Callback API', () => {
    describe('sign API', () => {
      it('returns an error on an unknown algorithm', done => {
        hsc.sign({algorithm: 'abc'}, (err, result) => {
          should.exist(err);
          should.not.exist(result);
          err.message.should.equal('Unknown algorithm \'abc\'.');
          done();
        });
      });

      describe('Ed25519', () => {
        it('creates a signature', done => {
          const plaintext = 'abc123';
          const {privateKeyBase58} = mockData.ed25519KeyPair;
          return hsc.sign(
            {algorithm: 'ed25519', plaintext, privateKeyBase58},
            (err, signature) => {
              should.not.exist(err);
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'q/tQqxBlhzSP+XTte7uYaaCyJXJvg8svdjV47E2rBrVI1fBIOAeKj5Jm7qB' +
                'kH0IL8CvKRboqHBCoITDrsT9DAQ==');
              done();
            });
        });
      });

      describe('HMAC', () => {
        it('creates a signature using sha256', () => {
          const plaintext = 'abc123';
          const sharedKey = 'secretKey';
          return hsc.sign(
            {algorithm: 'hmac', hashType: 'sha256', plaintext, sharedKey},
            (err, signature) => {
              should.not.exist(err);
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'FNAWrxLnd6YsyXGPvhZnoXvKERY+jzQ1TF2ucMmdEIA=');
            });
        });
        it('creates a signature using sha512', () => {
          const plaintext = 'abc123';
          const sharedKey = 'secretKey';
          return hsc.sign(
            {algorithm: 'hmac', hashType: 'sha512', plaintext, sharedKey},
            (err, signature) => {
              should.not.exist(err);
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'mnTTyVH8P4ymXE3dl6DRAZFSic2ElBvLH5yqjJziFZSm1B3ZI' +
                'V3r7KwKpbWasAZxPXjqZy8DnY8v++0+bVIQBQ==');
            });
        });
        it('returns an error on invalid `hashType`', () => {
          const plaintext = 'abc123';
          const sharedKey = 'secretKey';
          return hsc.sign(
            {algorithm: 'hmac', hashType: 'unknown', plaintext, sharedKey},
            (err, signature) => {
              should.exist(err);
              should.not.exist(signature);
              err.message.should.contain('Unknown message digest');
            });
        });
      });

      describe('RSA', () => {
        it('creates a signature using sha256', () => {
          const plaintext = 'abc123';
          const {privateKeyPem} = mockData.rsa2048KeyPair;
          return hsc.sign(
            {algorithm: 'rsa', hashType: 'sha256', plaintext, privateKeyPem},
            (err, signature) => {
              should.not.exist(err);
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'oHLS9K71TPOUQ7IG7Hdeq7jSmnoS6C2xyPvtlo56bizif1w/z' +
                '62OEIiFpz2Oe784vDcWEI7/x5fYdB/uqIfdbkaquI78OZpVCl' +
                'FVteTOmOw6EhQJ66hJLkml+8LnMSs0Y6v3Cd+wLsCfWpa/2PU' +
                'ZcLjv1AOV3vhYhTdTXl4ufCwdWuSpPtA8L4LC7rak5mb/wmNCt' +
                'iZ/Ol2/lhpwP6lPX+1UkH3EWFBTGDPnquk340TWRVXevrHDVSG' +
                'F6Z8CS0TEmx1eX2+R8PJlRJ/ExA0vWEAc7O7Y7KctKKU+wWobL' +
                'qftt9LGnThtWDKOHJlmQjt6k7S2WzvV5iIhVfLXee1tfw==');
            });
        });
        it('creates a signature using sha512', () => {
          const plaintext = 'abc123';
          const {privateKeyPem} = mockData.rsa2048KeyPair;
          return hsc.sign(
            {algorithm: 'rsa', hashType: 'sha512', plaintext, privateKeyPem},
            (err, signature) => {
              should.not.exist(err);
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'Pkfeqzy5qKRROV6BmakMFpK+JFcbxRrHHbB9qHDiUMmM+sj66kSLMml/+' +
                'T1lmCnWqXciupF1eG429j3Ulj706Ppog7AcvMSkSsKBy5WZ0yZCYqu6Fv' +
                'FOdpWiRqNvNAA+7YB2WdSutt8ABxP23Fk0+mROq8bZ4UHw5WOS69LyokJ' +
                'JwYt00HC8eK3MOuSdcjBrDAHh5EeoTN4hHTMlkpmY2SHYtjbyt9dIK2xX' +
                'VYvWyUIdrYHpBs4gyFV0aHd/q1tNfzpL0m1/oSRKbHfx3RURqArBdeJi0' +
                'N5CldSvFAMy4gT1elcsc5F3BRrEp1GkmzuwI+R80xWCVLi4Mbqn0xsADQ==');
            });
        });
        it('returns an error on invalid `hashType`', () => {
          const plaintext = 'abc123';
          const {privateKeyPem} = mockData.rsa2048KeyPair;
          return hsc.sign(
            {algorithm: 'rsa', hashType: 'unknown', plaintext, privateKeyPem},
            (err, signature) => {
              should.exist(err);
              should.not.exist(signature);
              err.message.should.contain('Unknown message digest');
            });
        });
      });
    });

    describe('verify API', () => {
      it('returns an error on an unknown algorithm', done => {
        hsc.verify({algorithm: 'abc'}, (err, result) => {
          should.exist(err);
          should.not.exist(result);
          err.message.should.equal('Unknown algorithm \'abc\'.');
          done();
        });
      });

      describe('Ed25519', () => {
        it('verifies a signature', () => {
          const plaintext = 'abc123';
          const {publicKeyBase58} = mockData.ed25519KeyPair;
          return hsc.verify({
            algorithm: 'ed25519', plaintext, publicKeyBase58,
            signature: 'q/tQqxBlhzSP+XTte7uYaaCyJXJvg8svdjV47E2rBrVI1fBIOAeK' +
              'j5Jm7qBkH0IL8CvKRboqHBCoITDrsT9DAQ=='
          }, (err, verified) => {
            should.not.exist(err);
            should.exist(verified);
            verified.should.be.a('boolean');
            verified.should.be.true;
          });
        });
      });

      describe('HMAC', () => {
        it('verifies a signature', () => {
          const plaintext = 'abc123';
          const sharedKey = 'secretKey';
          return hsc.verify({
            algorithm: 'hmac', hashType: 'sha512', plaintext, sharedKey,
            signature: 'mnTTyVH8P4ymXE3dl6DRAZFSic2ElBvLH5yqjJziFZSm1B3ZI' +
            'V3r7KwKpbWasAZxPXjqZy8DnY8v++0+bVIQBQ=='
          }, (err, verified) => {
            should.not.exist(err);
            should.exist(verified);
            verified.should.be.a('boolean');
            verified.should.be.true;
          });
        });
      });

      describe('RSA', () => {
        it('verifies a signature', () => {
          const plaintext = 'abc123';
          const {publicKeyPem} = mockData.rsa2048KeyPair;
          return hsc.verify({
            algorithm: 'rsa', hashType: 'sha512', plaintext, publicKeyPem,
            signature:
              'Pkfeqzy5qKRROV6BmakMFpK+JFcbxRrHHbB9qHDiUMmM+sj66kSLMml/+' +
              'T1lmCnWqXciupF1eG429j3Ulj706Ppog7AcvMSkSsKBy5WZ0yZCYqu6Fv' +
              'FOdpWiRqNvNAA+7YB2WdSutt8ABxP23Fk0+mROq8bZ4UHw5WOS69LyokJ' +
              'JwYt00HC8eK3MOuSdcjBrDAHh5EeoTN4hHTMlkpmY2SHYtjbyt9dIK2xX' +
              'VYvWyUIdrYHpBs4gyFV0aHd/q1tNfzpL0m1/oSRKbHfx3RURqArBdeJi0' +
              'N5CldSvFAMy4gT1elcsc5F3BRrEp1GkmzuwI+R80xWCVLi4Mbqn0xsADQ=='
          }, (err, verified) => {
            should.not.exist(err);
            should.exist(verified);
            verified.should.be.a('boolean');
            verified.should.be.true;
          });
        });
      });
    });
  });

});
