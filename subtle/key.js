'use strict';

const { InvalidAccessError } = require('./errors');

const kType = Symbol('kType');
const kAlgorithm = Symbol('kAlgorithm');
const kExtractable = Symbol('kExtractable');
const kUsages = Symbol('kUsages');

const kKeyMaterial = Symbol('kKeyMaterial');

// Spec: https://www.w3.org/TR/WebCryptoAPI/#cryptokey-interface
class CryptoKey {
  constructor(type, algorithm, extractable, usages, keyMaterial) {
    this[kType] = type;
    this[kAlgorithm] = algorithm;
    this[kExtractable] = extractable;
    this[kUsages] = new Set(usages);
    this[kKeyMaterial] = keyMaterial;
  }

  get type() {
    return this[kType];
  }

  get extractable() {
    return this[kExtractable];
  }

  get algorithm() {
    return this[kAlgorithm];
  }

  get usages() {
    return [...this[kUsages]];
  }
}

// Simple SecretKey class to simulate key object
class SecretKey {
  constructor(key) {
    this.key = key;
  }

  // Method to return the key in hex format
  export() {
    // return this.key.toString('hex');
    return Array.prototype.map.call(this.key, x => ('00' + x.toString(16)).slice(-2)).join('');
  }

  // Method to return the symmetric key size
  get symmetricKeySize() {
    return this.key.length;
  }

  get length() {
    return this.key.length;
  }
}


function createSecretKey(key) {
  // Convert the input key into a Uint8Array if it is not already one
  if (!(key instanceof Uint8Array)) {
    if (typeof key === 'string') {
      key = new TextEncoder().encode(key); // Use TextEncoder to convert string to Uint8Array
    } else if (Array.isArray(key)) {
      key = new Uint8Array(key); // Convert array to Uint8Array
    } else {
      throw new TypeError('Key must be a string, an array, or a Uint8Array');
    }
  }

  // Wrap the key in a SecretKey object
  const keyObject = new SecretKey(key);

  return keyObject;
}

function requireKeyUsage(key, usage) {
  if (!key[kUsages].has(usage))
    throw new InvalidAccessError();
}

module.exports = {
  kType,
  kAlgorithm,
  kExtractable,
  kUsages,
  kKeyMaterial,
  CryptoKey,
  requireKeyUsage
};
