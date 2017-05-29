"use strict";

const crypto = require("crypto");

const DataAtRest = require("../index.js");

test("encrypts and decrypts", () =>
    {
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
        expect(Buffer.isBuffer(cipherBundle.authTag)).toBe(true);
        expect(Buffer.isBuffer(cipherBundle.ciphertext)).toBe(true);
        expect(Buffer.isBuffer(cipherBundle.iv)).toBe(true);
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
        expect(randomData.equals(plaintext)).toBe(true);
    }
);

test("encrypts and decrypts ignoring extra cipher bundle fields", () =>
    {
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
        expect(Buffer.isBuffer(cipherBundle.authTag)).toBe(true);
        expect(Buffer.isBuffer(cipherBundle.ciphertext)).toBe(true);
        expect(Buffer.isBuffer(cipherBundle.iv)).toBe(true);
        cipherBundle.someExtraKeyField = "in case you want metadata in things";
        let plaintext =
                DataAtRest.decrypt(
                    cipherBundle,
                    DataAtRest.aad(aad),
                    key
                );
        expect(randomData.equals(plaintext)).toBe(true);
    }
);

test("decryption throws if authTag is changed", () =>
    {
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
        let invocation = () => DataAtRest.decrypt(cipherBundle, DataAtRest.aad(aad), key);
        expect(invocation).toThrow("Unsupported state or unable to authenticate data");
    }
);

test("decryption throws if aad is changed", () =>
    {
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
        let invocation = () => DataAtRest.decrypt(cipherBundle, DataAtRest.aad(aad), key);
        expect(invocation).toThrow("Unsupported state or unable to authenticate data");
    }
);

test("decryption throws if iv is changed", () =>
    {
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
        let invocation = () => DataAtRest.decrypt(cipherBundle, DataAtRest.aad(aad), key);
        expect(invocation).toThrow("Unsupported state or unable to authenticate data");
    }
);
