/// <reference path="../mcl.d.ts"/>

"use strict";
import {
    Commitment,
    SignatureProof,
    Signature,
    Issuer,
    User,
    Verifier,
    randomize,
    setup,
    verify
} from "../index";
import { expect } from "chai";
import "mocha";

describe("Unit tests for showing and checking a credential", () => {
    before(async () => {
        await setup();
    });

    it("should accept the showing of a valid signature", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = ["bahhh", "yeah"];
        const attributes: string[] = userAttr.concat(issuerAttr);
        const issuer: Issuer = new Issuer(attributes.length);
        const user: User = new User();
        const verifier: Verifier = new Verifier();

        const commitment = user.createCommitment(issuer.publicKey, userAttr);

        const blindSignature: Signature = issuer.blindSign(
            commitment,
            issuerAttr
        );

        const sig: Signature = user.unblindSignature(blindSignature);

        // just to make sure everything is ok so far
        expect(verify(issuer.publicKey, attributes, sig)).to.equal(true);

        const hiddenSetIdxs: number[] = [1, 2];
        const showAttributes: string[] = attributes.slice();
        hiddenSetIdxs.forEach(idx => {
            showAttributes[idx] = null;
        });

        expect(showAttributes).to.deep.equal([
            "ab",
            null,
            null,
            "scene",
            "bahhh",
            "yeah"
        ]);

        const proof: SignatureProof = user.proveKnowledgeOfSignature(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs
        );

        expect(
            verifier.checkSignatureProof(
                proof,
                issuer.publicKey,
                showAttributes
            )
        ).to.equal(true);
    });

    it("should accept the showing of a valid signature (using serialization)", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = ["bahhh", "yeah"];
        const attributes: string[] = userAttr.concat(issuerAttr);
        const issuer: Issuer = new Issuer(attributes.length);
        const user: User = new User();
        const verifier: Verifier = new Verifier();

        const commitment = user.createCommitment(issuer.publicKey, userAttr);

        const blindSignature: Signature = issuer.blindSign(
            commitment,
            issuerAttr
        );

        const sig: Signature = user.unblindSignature(blindSignature);

        // just to make sure everything is ok so far
        expect(verify(issuer.publicKey, attributes, sig)).to.equal(true);

        const hiddenSetIdxs: number[] = [1, 2];
        const showAttributes: string[] = attributes.slice();
        hiddenSetIdxs.forEach(idx => {
            showAttributes[idx] = null;
        });

        expect(showAttributes).to.deep.equal([
            "ab",
            null,
            null,
            "scene",
            "bahhh",
            "yeah"
        ]);

        const proof: SignatureProof = user.proveKnowledgeOfSignature(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs
        );
        const srlProof: string = proof.serialize();
        /**
         * User ------------------------ {proof} ------------------------> Verifier
         */
        const rcvProof: SignatureProof = SignatureProof.deserialize(srlProof);

        expect(
            verifier.checkSignatureProof(
                rcvProof,
                issuer.publicKey,
                showAttributes
            )
        ).to.equal(true);
    });

    it("should reject the showing of a signature by a fake issuer", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = ["bahhh", "yeah"];
        const attributes: string[] = userAttr.concat(issuerAttr);
        const issuer: Issuer = new Issuer(attributes.length);
        const fakeIssuer: Issuer = new Issuer(attributes.length);
        const user: User = new User();
        const verifier: Verifier = new Verifier();

        const commitment = user.createCommitment(
            fakeIssuer.publicKey,
            userAttr
        );

        const blindSignature: Signature = fakeIssuer.blindSign(
            commitment,
            issuerAttr
        );

        const sig: Signature = user.unblindSignature(blindSignature);

        const hiddenSetIdxs: number[] = [1, 2];
        const showAttributes: string[] = attributes.slice();
        hiddenSetIdxs.forEach(idx => {
            showAttributes[idx] = null;
        });

        expect(showAttributes).to.deep.equal([
            "ab",
            null,
            null,
            "scene",
            "bahhh",
            "yeah"
        ]);

        const proof: SignatureProof = user.proveKnowledgeOfSignature(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs
        );

        expect(
            verifier.checkSignatureProof(
                proof,
                issuer.publicKey,
                showAttributes
            )
        ).to.equal(false);
    });
});
