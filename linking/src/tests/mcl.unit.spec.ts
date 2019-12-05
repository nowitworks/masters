/// <reference path="../mcl.d.ts"/>

"use strict";
import "mocha";
import { expect } from "chai";
import * as mcl1 from "mcl-wasm";
import * as mcl2 from "mcl-wasm";
// import { mcl as mcl2 } from "../linking";


function randomFr1(): mcl1.Fr {
    const a: mcl1.Fr = new mcl1.Fr();
    a.setByCSPRNG();
    return a;
}

function randomFr2(): mcl2.Fr {
    const a: mcl2.Fr = new mcl2.Fr();
    a.setByCSPRNG();
    return a;
}

describe("Unit tests for inter-instance compatibility", () => {
    before(async () => {
        await mcl1.init(mcl1.BN254);
        await mcl2.init(mcl2.BN254);
    })

    it("should use two different instances of mcl working together", () => {
        // This means the problem with mcl is not really the problem of having two instances
        // It's something related to the fact that it's using stuff from another library
        // TODO should try to figure this out
        const a1: mcl1.Fr = randomFr1();
        const a2: mcl2.Fr = randomFr2();

        expect(mcl1.mul(a1, a2).getStr()).to.be.string;
        expect(a1 instanceof mcl2.Fr).to.be.true;
        expect(a2 instanceof mcl1.Fr).to.be.true;
    });
});
