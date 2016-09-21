"use strict";

const DataAtRest = require("../index.js");

const tests = module.exports = {};

tests["aad sorts object keys"] = test =>
{
    test.expect(1);
    let obj =
    {
        second: 2,
        first: 1
    };
    test.equal(DataAtRest.aad(obj).toString("utf8"), `{"first":1,"second":2}`);
    test.done();
};

tests["aad throws if nested objects"] = test =>
{
    test.expect(1);
    let obj =
    {
        second: 2,
        first:
        {
            second: 22,
            first: 11
        }
    };
    test.throws(() => DataAtRest.aad(obj), TypeError);
    test.done();
}
