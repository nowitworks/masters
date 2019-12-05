/// <reference path="../mcl.d.ts"/>

"use strict";
import { Signature } from "../ps-types";
import { KeyPair, randomize, setup, sign, verify } from "../ps-sigs";
import { expect } from "chai";
import "mocha";

describe("Integration tests for ps-sigs", () => {
    before(async () => {
        await setup();
    });

    it("should accept a valid signature", () => {
        const messages: string[] = ["ab", "noooo", "msg", "scene"];

        const keyPair: KeyPair = new KeyPair(messages.length);

        const sig: Signature = sign(keyPair.secretKey, messages);

        expect(verify(keyPair.publicKey, messages, sig)).to.equal(true);
    });

    it("should reject an invalid signature on the messages", () => {
        const messages: string[] = ["ab", "noooo", "msg", "scene"];

        const keyPair: KeyPair = new KeyPair(messages.length);

        const sig: Signature = sign(keyPair.secretKey, messages);

        const fakeMessages: string[] = ["ba", "oooon", "mgs", "scent"];
        expect(verify(keyPair.publicKey, fakeMessages, sig)).to.equal(false);
    });

    it("should accept a valid and reject an invalid signature", () => {
        const messages: string[] = ["ab", "noooo", "msg", "scene"];

        const keyPair: KeyPair = new KeyPair(messages.length);

        const sig: Signature = sign(keyPair.secretKey, messages);

        expect(verify(keyPair.publicKey, messages, sig)).to.equal(true);

        const fakeMessages: string[] = ["ba", "oooon", "mgs", "scent"];
        expect(verify(keyPair.publicKey, fakeMessages, sig)).to.equal(false);
    });

    it("should accept a valid signature after randomization", () => {
        const messages: string[] = ["ab", "noooo", "msg", "scene"];
        const keyPair: KeyPair = new KeyPair(messages.length);

        const randSig: Signature = randomize(sign(keyPair.secretKey, messages));

        expect(verify(keyPair.publicKey, messages, randSig)).to.equal(true);
    });

    it("should reject an invalid signature after randomization", () => {
        const messages: string[] = ["ab", "noooo", "msg", "scene"];
        const keyPair: KeyPair = new KeyPair(messages.length);

        const randSig: Signature = randomize(sign(keyPair.secretKey, messages));

        const fakeMessages: string[] = ["ba", "oooon", "mgs", "scent"];
        expect(verify(keyPair.publicKey, fakeMessages, randSig)).to.equal(
            false
        );
    });

    it("should fail because of missing message in array", () => {
        const messages: string[] = ["ab", "noooo", "msg", "scene"];
        const keyPair: KeyPair = new KeyPair(messages.length);

        const sig: Signature = sign(keyPair.secretKey, messages);

        const messagesIncomplete: string[] = ["ab", "noooo", "msg"];
        expect(() =>
            verify(keyPair.publicKey, messagesIncomplete, sig)
        ).to.throw(Error);
    });
});
