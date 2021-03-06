# data-at-rest

_Stability: 1 - [Experimental](https://github.com/tristanls/stability-index#stability-1---experimental)_

[![NPM version](https://badge.fury.io/js/data-at-rest.png)](http://npmjs.org/package/data-at-rest)

Encryption utilities for data at rest.

## Contributors

[@tristanls](https://github.com/tristanls)

## Contents

  * [Overview](#overview)
  * [Installation](#installation)
  * [Tests](#tests)
  * [Usage](#usage)
  * [Documentation](#documentation)
  * [Releases](#releases)

## Overview

This module encodes a way to store secret data at rest given an encryption `key`. It is intended to guide the user by providing default algorithm selection (`DataAtRest.ALGORITHM`), asking for additional authenticated data, specifying appropriate initialization vector length (`DataAtRest.IV_LENGTH_IN_BYTES`), and using `crypto.createCipheriv()` instead of `crypto.createCipher()`.

Generation and management of encryption `key` is beyond the scope of this module, however [Envelope encryption](http://docs.aws.amazon.com/kms/latest/developerguide/workflow.html) may be of interest.

For more insight into additional authenticated data and its uses, see [How to Protect the Integrity of Your Encrypted Data by Using AWS Key Management Service and EncryptionContext](http://blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management).

## Installation

    npm install data-at-rest

## Tests

    npm test

## Usage

```javascript
const DataAtRest = require("data-at-rest");

// secret key from somewhere
const key = crypto.randomBytes(32); // 256 bits (aes-256-gcm)

// data to store
const data = {
    id: "some-id",
    secretData: "some secret data",
    notSecretData: "not secret data"
};

// encryption
const additionalAuthenticatedData = {
    id: data.id,
    notSecretData: data.notSecretData
};
const cipherBundle =
            DataAtRest.encrypt(
                Buffer.from(data.secretData, "utf8"),
                DataAtRest.aad(additionalAuthenticatedData),
                key
            );
const dataStoredAtRest = {
    id: data.id,
    secretData: JSON.stringify(DataAtRest.cipherBundleToBase64(cipherBundle)),
    notSecretData: data.notSecretData
};

// decryption
const plaintext =
            DataAtRest.decrypt(
                DataAtRest.cipherBundleFromBase64(JSON.parse(dataStoredAtRest.secretData)),
                DataAtRest.aad(additionalAuthenticatedData),
                key
            );
const retrievedData = {
    id: dataStoredAtRest.id,
    secretData: plaintext.toString("utf8"),
    notSecretData: dataStoredAtRest.notSecretData
};
```

## Documentation

### DataAtRest

**Public API**
  * [DataAtRest.ALGORITHM](#dataatrestalgorithm)
  * [DataAtRest.IV_LENGTH_IN_BYTES](#dataatrestiv_length_in_bytes)
  * [DataAtRest.aad(obj)](#dataatrestaadobj)
  * [DataAtRest.cipherBundleFromBase64(cipherBundle)](#dataatrestcipherbundlefrombase64cipherbundle)
  * [DataAtRest.cipherBundleToBase64(cipherBundle)](#dataatrestcipherbundletobase64cipherbundle)
  * [DataAtRest.decrypt(cipherBundle, aad, key)](#dataatrestdecryptcipherbundle-aad-key)
  * [DataAtRest.encrypt(plaintext, aad, key)](#dataatrestencryptplaintext-aad-key)
  * [DataAtRest.normalizeAad(obj)](#dataatrestnormalizeaadobj)

#### DataAtRest.ALGORITHM

  * `aes-256-gcm`

Default algorithm to use.

#### DataAtRest.IV_LENGTH_IN_BYTES

  * `12`

Default initialization vector length in bytes.

#### DataAtRest.aad(obj)

  * `obj`: _Object_ An object representing string-to-string map of additional authenticated data.
  * Return: _Buffer_ Normalized additional authenticated data.

Normalizes given additional authenticated data by sorting it in order to generate the same buffer regardless of property ordering within the passed in object.

#### DataAtRest.cipherBundleFromBase64(cipherBundle)

  * `cipherBundle`: _Object_ Cipher bundle generated by [DataAtRest.cipherBundleToBase64(cipherBundle)](#dataatrestcipherbundletobase64cipherbundle).
    * `authTag`: _String_ Base64 encoded string authentication tag.
    * `ciphertext`: _String_ Base64 encoded string ciphertext.
    * `iv`: _String_ Base64 encoded string initialization vector.
  * Return: _Object_ Cipher bundle with Base64 encoded strings converted to Buffers.
    * `authTag`: _Buffer_ Authentication tag.
    * `ciphertext`: _Buffer_ Ciphertext.
    * `iv`: _Buffer_ Initialization vector.

Converts a cipher bundle with Base64 encoded string properties into a cipher bundle with Buffer properties.

#### DataAtRest.cipherBundleToBase64(cipherBundle)

  * `cipherBundle`: _Object_ Cipher bundle generated by [DataAtRest.encrypt(plaintext, aad, key)](#dataatrestencryptplaintext-aad-key).
    * `authTag`: _Buffer_ Authentication tag.
    * `ciphertext`: _Buffer_ Ciphertext.
    * `iv`: _Buffer_ Initialization vector.
  * Return: _Object_ Cipher bundle with Buffers converted to Base64 encoded strings.
    * `authTag`: _String_ Base64 encoded string authentication tag.
    * `ciphertext`: _String_ Base64 encoded string ciphertext.
    * `iv`: _String_ Base64 encoded string initialization vector.

Converts a cipher bundle with Buffer properties into a cipher bundle with Base64 encoded string properties.

#### DataAtRest.decrypt(cipherBundle, aad, key)

  * `cipherBundle`: _Object_ Cipher bundle generated by [DataAtRest.encrypt(plaintext, aad, key)](#dataatrestencryptplaintext-aad-key).
    * `authTag`: _Buffer_ Authentication tag.
    * `ciphertext`: _Buffer_ Ciphertext.
    * `iv`: _Buffer_ Initialization vector.
  * `aad`: _Buffer_ Additional authenticated data generated by [DataAtRest.aad(obj)](#dataatrestaadobj).
  * `key`: _Buffer_ Encryption key.
  * Return: _Buffer_ Decrypted plaintext.

Decrypts previously encrypted `cipherBundle` into `plaintext`.

#### DataAtRest.encrypt(plaintext, aad, key)

  * `plaintext`: _Buffer_ Plaintext to encrypt.
  * `aad`: _Buffer_ Additional authenticated data generated by [DataAtRest.aad(obj)](#dataatrestaadobj).
  * `key`: _Buffer_ Encryption key.
  * Return: _Object_ Cipher bundle.
    * `authTag`: _Buffer_ Authentication tag.
    * `ciphertext`: _Buffer_ Ciphertext.
    * `iv`: _Buffer_ Initialization vector.

Encrypts the `plaintext` using specified additional authenticated data (`aad`) and the encryption `key`.

#### DataAtRest.normalizeAad(obj)

  * `obj`: _Object_ An object representing string-to-string map of additional authenticated data.
  * Return: _Array_ Normalized object in form of sorted array.

Normalizes given additional authenticated data object by sorting it by key and returning an array (the order of which should be preserved by `JSON.stringify` implementations).

## Releases

[Current releases](https://github.com/tristanls/data-at-rest/releases).

### Policy

We follow the semantic versioning policy ([semver.org](http://semver.org/)) with a caveat:

> Given a version number MAJOR.MINOR.PATCH, increment the:
>
>MAJOR version when you make incompatible API changes,<br/>
>MINOR version when you add functionality in a backwards-compatible manner, and<br/>
>PATCH version when you make backwards-compatible bug fixes.

**caveat**: Major version zero is a special case indicating development version that may make incompatible API changes without incrementing MAJOR version.
