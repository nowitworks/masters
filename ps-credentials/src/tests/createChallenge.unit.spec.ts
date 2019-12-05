/// <reference path="../mcl.d.ts"/>

"use strict";
import { setup } from "../index";
import { createChallenge } from "../ps-internal";
import { expect } from "chai";
import "mocha";
import { Fr, G1, G2, hashToFr, hashAndMapToG1, hashAndMapToG2 } from "mcl-wasm";

describe("Unit tests for createChallenge function", () => {
    before(async () => {
        await setup();
    });

    it("should return the same output for the same inputs", () => {
        const a: Fr = hashToFr("randomA");
        const b: G1 = hashAndMapToG1("randomB");
        const c: G2 = hashAndMapToG2("randomC");

        expect(createChallenge(a, b, c)).to.deep.equal(
            createChallenge(a, b, c)
        );
        expect(createChallenge(b, c, a)).to.deep.equal(
            createChallenge(b, c, a)
        );
        expect(createChallenge(c, a, b)).to.deep.equal(
            createChallenge(c, a, b)
        );
    });

    it("should return different outputs for different inputs", () => {
        const a: Fr = hashToFr("randomA");
        const b: G1 = hashAndMapToG1("randomB");
        const c: G2 = hashAndMapToG2("randomC");

        expect(createChallenge(a, b, c)).to.not.deep.equal(
            createChallenge(a, b, b)
        );
        expect(createChallenge(a, b, c)).to.not.deep.equal(
            createChallenge(c, b, a)
        );
        expect(createChallenge(a, b, c)).to.not.deep.equal(
            createChallenge(a, b, c, c)
        );
        expect(createChallenge(a, b, c, a)).to.not.deep.equal(
            createChallenge(a, a, a, a)
        );
        expect(createChallenge(a, b, c, a)).to.not.deep.equal(
            createChallenge(a, b, c, c)
        );
    });
});
