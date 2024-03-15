'use strict';

// TODO: Commented code has crypto import which makes it unsupported for now

const { AES_CTR, AES_CBC, AES_GCM, AES_KW } = require('./algorithms/aes');
const { ECDH } = require('./algorithms/ecdh');
// const { ECDSA } = require('./algorithms/ecdsa');
const { HKDF } = require('./algorithms/hkdf');
const { HMAC } = require('./algorithms/hmac');
const { PBKDF2 } = require('./algorithms/pbkdf2');
// const { RSASSA_PKCS1, RSA_PSS, RSA_OAEP } = require('./algorithms/rsa');
const { SHA_1, SHA_256, SHA_384, SHA_512 } = require('./algorithms/sha');
const { NotSupportedError } = require('./errors');
const { requireDOMString } = require('./idl');

const algorithms = [
  AES_CTR,
  AES_CBC,
  AES_GCM,
  AES_KW,

  ECDH,

  // ECDSA,

  HKDF,

  HMAC,

  PBKDF2,

  // RSASSA_PKCS1,
  // RSA_PSS,
  // RSA_OAEP,

  SHA_1,
  SHA_256,
  SHA_384,
  SHA_512
];

function objectFromArray(array, fn) {
  const obj = {};
  for (const val of array)
    fn(obj, val);
  return obj;
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#dfn-supportedAlgorithms
const supportedAlgorithms = objectFromArray([
  // This corresponds to section 18.2.2 of the WebCrypto spec.
  'encrypt',
  'decrypt',
  'sign',
  'verify',
  'deriveBits',
  'wrapKey',
  'unwrapKey',
  'digest',
  'generateKey',
  'importKey',
  'exportKey',
  'get key length',

  // The following APIs are for internal use only.
  'get hash function',
  'get hash block size'
], (opsByName, op) => {
  opsByName[op] = objectFromArray(algorithms, (algsByName, alg) => {
    if (typeof alg[op] === 'function')
      algsByName[alg.name.toLowerCase()] = alg;
  });
});

function getAlgorithm(alg, op) {
  if (typeof alg === 'object') {
    return getAlgorithm(alg.name, op);
  }

  requireDOMString(alg);
  console.log("break alg", alg, op);
  const impl = supportedAlgorithms[op][alg.toLowerCase()];
  console.log("break supported alog", supportedAlgorithms);
  console.log("break impl", impl)
  if (impl === undefined)
    throw new NotSupportedError();
  return impl;
}

module.exports.getAlgorithm = getAlgorithm;
