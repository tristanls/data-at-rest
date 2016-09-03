"use strict";

const crypto = require("crypto");

const DataAtRest = require("../index.js");

const tests = module.exports = {};

tests["encrypts and decrypts"] = test =>
{
    test.expect(4);
    let key = crypto.randomBytes(32); // 256 bits (aes256)
    let randomData = crypto.randomBytes(42);
    let aad = {
        some: crypto.randomBytes(10).toString("base64"),
        additional: crypto.randomBytes(15).toString("base64"),
        authenticated: crypto.randomBytes(20).toString("base64"),
        data: crypto.randomBytes(25).toString("base64")
    };
    let cipherBundle =
            DataAtRest.encrypt(
                randomData,
                DataAtRest.aad(aad),
                key
            );
    test.ok(Buffer.isBuffer(cipherBundle.authTag));
    test.ok(Buffer.isBuffer(cipherBundle.ciphertext));
    test.ok(Buffer.isBuffer(cipherBundle.iv));
    aad = { // test that aad normalization happens by changing key ordering here
        authenticated: aad.authenticated,
        additional: aad.additional,
        data: aad.data,
        some: aad.some
    };
    let plaintext =
            DataAtRest.decrypt(
                cipherBundle,
                DataAtRest.aad(aad),
                key
            );
    test.ok(randomData.equals(plaintext));
    test.done();
};

tests["encrypts and decrypts ignoring extra cipher bundle fields"] = test =>
{
    test.expect(4);
    let key = crypto.randomBytes(32); // 256 bits (aes256)
    let randomData = crypto.randomBytes(42);
    let aad = {
        some: crypto.randomBytes(10).toString("base64"),
        additional: crypto.randomBytes(15).toString("base64"),
        authenticated: crypto.randomBytes(20).toString("base64"),
        data: crypto.randomBytes(25).toString("base64")
    };
    let cipherBundle =
            DataAtRest.encrypt(
                randomData,
                DataAtRest.aad(aad),
                key
            );
    test.ok(Buffer.isBuffer(cipherBundle.authTag));
    test.ok(Buffer.isBuffer(cipherBundle.ciphertext));
    test.ok(Buffer.isBuffer(cipherBundle.iv));
    cipherBundle.someExtraKeyField = "in case you want metadata in things";
    let plaintext =
            DataAtRest.decrypt(
                cipherBundle,
                DataAtRest.aad(aad),
                key
            );
    test.ok(randomData.equals(plaintext));
    test.done();
};

tests["decryption throws if authTag is changed"] = test =>
{
    test.expect(1);
    let key = crypto.randomBytes(32); // 256 bits (aes256)
    let randomData = crypto.randomBytes(42);
    let aad = {
        some: crypto.randomBytes(10).toString("base64"),
        additional: crypto.randomBytes(15).toString("base64"),
        authenticated: crypto.randomBytes(20).toString("base64"),
        data: crypto.randomBytes(25).toString("base64")
    };
    let cipherBundle =
            DataAtRest.encrypt(
                randomData,
                DataAtRest.aad(aad),
                key
            );
    cipherBundle.authTag = crypto.randomBytes(cipherBundle.authTag.length);
    test.throws(() =>
    {
        DataAtRest.decrypt(
            cipherBundle,
            DataAtRest.aad(aad),
            key
        );
    }, Error);
    test.done();
};

tests["decryption throws if aad is changed"] = test =>
{
    test.expect(1);
    let key = crypto.randomBytes(32); // 256 bits (aes256)
    let randomData = crypto.randomBytes(42);
    let aad = {
        some: crypto.randomBytes(10).toString("base64"),
        additional: crypto.randomBytes(15).toString("base64"),
        authenticated: crypto.randomBytes(20).toString("base64"),
        data: crypto.randomBytes(25).toString("base64")
    };
    let cipherBundle =
            DataAtRest.encrypt(
                randomData,
                DataAtRest.aad(aad),
                key
            );
    aad.foo = "bar";
    test.throws(() =>
    {
        DataAtRest.decrypt(
            cipherBundle,
            DataAtRest.aad(aad),
            key
        );
    }, Error);
    test.done();
};

tests["decryption throws if iv is changed"] = test =>
{
    test.expect(1);
    let key = crypto.randomBytes(32); // 256 bits (aes256)
    let randomData = crypto.randomBytes(42);
    let aad = {
        some: crypto.randomBytes(10).toString("base64"),
        additional: crypto.randomBytes(15).toString("base64"),
        authenticated: crypto.randomBytes(20).toString("base64"),
        data: crypto.randomBytes(25).toString("base64")
    };
    let cipherBundle =
            DataAtRest.encrypt(
                randomData,
                DataAtRest.aad(aad),
                key
            );
    cipherBundle.iv = crypto.randomBytes(cipherBundle.iv.length);
    test.throws(() =>
    {
        DataAtRest.decrypt(
            cipherBundle,
            DataAtRest.aad(aad),
            key
        );
    }, Error);
    test.done();
};
