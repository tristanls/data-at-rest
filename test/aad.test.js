"use strict";

const DataAtRest = require("../index.js");

describe("aad", () =>
    {
        it("sorts object keys", () =>
            {
                let obj =
                {
                    second: 2,
                    first: 1
                };
                expect(DataAtRest.aad(obj).toString("utf8")).toBe(`{"first":1,"second":2}`);
            }
        );
        it("throws if nested object", () =>
            {
                let obj =
                {
                    second: 2,
                    first:
                    {
                        second: 22,
                        first: 11
                    }
                };
                let invocation = () => DataAtRest.aad(obj);
                expect(invocation).toThrow(TypeError);
            }
        );
    }
);
