"use strict";

const assert = require("assert");
const crypto = require("crypto");

const DataAtRest = module.exports;

DataAtRest.ALGORITHM = "aes-256-gcm";
DataAtRest.IV_LENGTH_IN_BYTES = 12; // 96 bits

DataAtRest.aad = obj =>
{
    return Buffer.from(
                JSON.stringify(
                    Object.keys(obj)
                        .sort()
                        .reduce((result, property) =>
                        {
                            if (typeof obj[property] == "object")
                            {
                                throw new TypeError("DataAtRest.aad() does not accept nested objects.");
                            }
                            result[property] = obj[property];
                            return result;
                        },
                        {})
                ),
                "utf8");
};

DataAtRest.cipherBundleFromBase64 = cipherBundle =>
{
    assert.ok(typeof cipherBundle.authTag === "string", "cipherBundle.authTag is not a String");
    assert.ok(typeof cipherBundle.ciphertext === "string", "cipherBundle.ciphertext is not a String");
    assert.ok(typeof cipherBundle.iv === "string", "cipherBundle.iv is not a String");
    return {
        authTag: Buffer.from(cipherBundle.authTag, "base64"),
        ciphertext: Buffer.from(cipherBundle.ciphertext, "base64"),
        iv: Buffer.from(cipherBundle.iv, "base64")
    };
};

DataAtRest.cipherBundleToBase64 = cipherBundle =>
{
    assert.ok(Buffer.isBuffer(cipherBundle.authTag), "cipherBundle.authTag is not a Buffer");
    assert.ok(Buffer.isBuffer(cipherBundle.ciphertext), "cipherBundle.ciphertext is not a Buffer");
    assert.ok(Buffer.isBuffer(cipherBundle.iv), "cipherBundle.iv is not a Buffer");
    return {
        authTag: cipherBundle.authTag.toString("base64"),
        ciphertext: cipherBundle.ciphertext.toString("base64"),
        iv: cipherBundle.iv.toString("base64")
    };
};

DataAtRest.decrypt = (cipherBundle, aad, key) =>
{
    assert.ok(Buffer.isBuffer(cipherBundle.authTag), "cipherBundle.authTag is not a Buffer");
    assert.ok(Buffer.isBuffer(cipherBundle.ciphertext), "cipherBundle.ciphertext is not a Buffer");
    assert.ok(Buffer.isBuffer(cipherBundle.iv), "cipherBundle.iv is not a Buffer");
    assert.ok(Buffer.isBuffer(aad), "aad is not a Buffer");
    assert.ok(Buffer.isBuffer(key), "key is not a Buffer");
    const decipher = crypto.createDecipheriv(DataAtRest.ALGORITHM, key, cipherBundle.iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(cipherBundle.authTag);
    return Buffer.concat([decipher.update(cipherBundle.ciphertext), decipher.final()]);
};

DataAtRest.encrypt = (plaintext, aad, key) =>
{
    assert.ok(Buffer.isBuffer(plaintext), "plaintext is not a Buffer");
    assert.ok(Buffer.isBuffer(aad), "aad is not a Buffer");
    assert.ok(Buffer.isBuffer(key), "key is not a Buffer");
    const iv = crypto.randomBytes(DataAtRest.IV_LENGTH_IN_BYTES);
    const cipher = crypto.createCipheriv(DataAtRest.ALGORITHM, key, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
        authTag,
        ciphertext,
        iv
    };
};
