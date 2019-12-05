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

describe("Integration tests for ps-credentials", () => {
    before(async () => {
        await setup();
    });

    it("should accept a valid unblinded signature", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = ["bahhh", "yeah"];
        const issuer: Issuer = new Issuer(userAttr.length + issuerAttr.length);
        const user: User = new User();

        const commitment = user.createCommitment(issuer.publicKey, userAttr);

        /**
         * User ------------------------ {commitment} ------------------------> Issuer
         */

        const blindSignature: Signature = issuer.blindSign(
            commitment,
            issuerAttr
        );

        /**
         * User <--------------------- {blindSignature} ----------------------- Issuer
         */

        const sig: Signature = user.unblindSignature(blindSignature);

        expect(
            verify(issuer.publicKey, userAttr.concat(issuerAttr), sig)
        ).to.equal(true);
    });

    it("should accept a valid unblinded signature (using serialization)", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = ["bahhh", "yeah"];
        const issuer: Issuer = new Issuer(userAttr.length + issuerAttr.length);
        const user: User = new User();

        const commitment: Commitment = user.createCommitment(
            issuer.publicKey,
            userAttr
        );
        const srlCommitment: string = commitment.serialize();
        /**
         * User ------------------------ {commitment} ------------------------> Issuer
         */
        const rcvCommitment: Commitment = Commitment.deserialize(srlCommitment);

        const blindSignature: Signature = issuer.blindSign(
            rcvCommitment,
            issuerAttr
        );
        const srlBlindSignature: string = blindSignature.serialize();
        /**
         * User <--------------------- {blindSignature} ----------------------- Issuer
         */
        const rcvBlindSignature: Signature = Signature.deserialize(
            srlBlindSignature
        );

        const sig: Signature = user.unblindSignature(rcvBlindSignature);

        expect(
            verify(issuer.publicKey, userAttr.concat(issuerAttr), sig)
        ).to.equal(true);
    });

    it("should accept a valid unblinded signature with no issuer defined attributes", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = [];
        const issuer: Issuer = new Issuer(userAttr.length + issuerAttr.length);
        const user: User = new User();

        const commitment = user.createCommitment(issuer.publicKey, userAttr);

        const blindSignature: Signature = issuer.blindSign(
            commitment,
            issuerAttr
        );

        const sig: Signature = user.unblindSignature(blindSignature);

        expect(
            verify(issuer.publicKey, userAttr.concat(issuerAttr), sig)
        ).to.equal(true);
    });

    it("should reject a blind signature", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = ["bahhh", "yeah"];
        const issuer: Issuer = new Issuer(userAttr.length + issuerAttr.length);
        const user: User = new User();

        const commitment = user.createCommitment(issuer.publicKey, userAttr);

        const blindSignature: Signature = issuer.blindSign(
            commitment,
            issuerAttr
        );

        expect(
            verify(
                issuer.publicKey,
                userAttr.concat(issuerAttr),
                blindSignature
            )
        ).to.equal(false);
    });

    it("should accept a randomized valid unblinded signature", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = [];
        const issuer: Issuer = new Issuer(userAttr.length + issuerAttr.length);
        const user: User = new User();

        const commitment = user.createCommitment(issuer.publicKey, userAttr);

        const blindSignature: Signature = issuer.blindSign(
            commitment,
            issuerAttr
        );

        const sig: Signature = user.unblindSignature(blindSignature);

        expect(
            verify(
                issuer.publicKey,
                userAttr.concat(issuerAttr),
                randomize(sig)
            )
        ).to.equal(true);
    });

    it("should reject a randomized blind signature", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = [];
        const issuer: Issuer = new Issuer(userAttr.length + issuerAttr.length);
        const user: User = new User();

        const commitment = user.createCommitment(issuer.publicKey, userAttr);

        const blindSignature: Signature = issuer.blindSign(
            commitment,
            issuerAttr
        );

        expect(
            verify(
                issuer.publicKey,
                userAttr.concat(issuerAttr),
                randomize(blindSignature)
            )
        ).to.equal(false);
    });

    it("should reject a signature by a fake issuer", () => {
        const userAttr: string[] = ["ab", "noooo", "msg", "scene"];
        const issuerAttr: string[] = ["bahhh", "yeah"];
        const issuer: Issuer = new Issuer(userAttr.length + issuerAttr.length);
        const fakeIssuer: Issuer = new Issuer(
            userAttr.length + issuerAttr.length
        );
        const user: User = new User();

        const commitment = user.createCommitment(
            fakeIssuer.publicKey,
            userAttr
        );

        const fakeBlindSignature: Signature = fakeIssuer.blindSign(
            commitment,
            issuerAttr
        );

        const fakeSig: Signature = user.unblindSignature(fakeBlindSignature);

        expect(
            verify(issuer.publicKey, userAttr.concat(issuerAttr), fakeSig)
        ).to.equal(false);
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
