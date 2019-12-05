/// <reference path="../mcl.d.ts"/>

"use strict";
import {
    Commitment,
    Pseudonym,
    SignatureProof,
    Signature,
    Issuer,
    User,
    Verifier,
    setup,
    verify
} from "../index";
import { expect } from "chai";
import "mocha";

describe("Integration tests for ps-credentials with domain-specific pseudonyms", () => {
    let userAttr: string[];
    let issuerAttr: string[];
    let attributes: string[];
    let issuer: Issuer;
    let user: User;
    let verifier: Verifier;
    let commitment: Commitment;
    let blindSignature: Signature;
    let sig: Signature;
    let hiddenSetIdxs: number[];
    let showAttributes: string[];
    let keyIdx: number;
    let domain: string;
    let nym: Pseudonym;

    before(async () => {
        await setup();

        userAttr = ["ab", "noooo", "secretKey", "scene"];
        issuerAttr = ["bahhh", "yeah"];
        attributes = userAttr.concat(issuerAttr);

        issuer = new Issuer(attributes.length);
        user = new User();
        verifier = new Verifier();

        commitment = user.createCommitment(issuer.publicKey, userAttr);

        blindSignature = issuer.blindSign(commitment, issuerAttr);

        sig = user.unblindSignature(blindSignature);

        hiddenSetIdxs = [1, 2];
        showAttributes = attributes.slice();
        hiddenSetIdxs.forEach(idx => {
            showAttributes[idx] = null;
        });

        // for the pseudonym
        keyIdx = 2;
        domain = "test123@tool.epfl.ch";
        nym = user.createDomainSpecificNym(domain, attributes[keyIdx]);
    });

    it("should accept the showing of a valid signature and pseudonym", () => {
        // just to make sure everything is ok so far
        expect(verify(issuer.publicKey, attributes, sig)).to.equal(true);

        const proof: SignatureProof = user.proveKnowledgeOfSignatureAndNym(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs,
            nym,
            keyIdx
        );

        expect(
            verifier.checkSignatureProofAndNym(
                proof,
                issuer.publicKey,
                showAttributes,
                nym,
                keyIdx
            )
        ).to.equal(true);
    });

    it("should accept the showing of a valid signature and pseudonym (using serialization)", () => {
        // just to make sure everything is ok so far
        expect(verify(issuer.publicKey, attributes, sig)).to.equal(true);

        const proof: SignatureProof = user.proveKnowledgeOfSignatureAndNym(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs,
            nym,
            keyIdx
        );
        const srlProof: string = proof.serialize();
        const srlNym: string = nym.serialize();
        /**
         * User ------------------------ {proof} ------------------------> Verifier
         */
        const rcvProof: SignatureProof = SignatureProof.deserialize(srlProof);
        const rcvNym: Pseudonym = Pseudonym.deserialize(srlNym);

        expect(
            verifier.checkSignatureProofAndNym(
                rcvProof,
                issuer.publicKey,
                showAttributes,
                rcvNym,
                keyIdx
            )
        ).to.equal(true);
    });

    it("should reject the showing of a signature by a fake issuer but with a valid pseudonym", () => {
        const fakeIssuer: Issuer = new Issuer(attributes.length);

        const commitment: Commitment = user.createCommitment(
            fakeIssuer.publicKey,
            userAttr
        );

        const blindSignature: Signature = fakeIssuer.blindSign(
            commitment,
            issuerAttr
        );

        const sig: Signature = user.unblindSignature(blindSignature);

        const proof: SignatureProof = user.proveKnowledgeOfSignatureAndNym(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs,
            nym,
            keyIdx
        );

        expect(
            verifier.checkSignatureProofAndNym(
                proof,
                issuer.publicKey,
                showAttributes,
                nym,
                keyIdx
            )
        ).to.equal(false);
    });

    it("should reject the showing of a valid signature but with an invalid pseudonym", () => {
        // just to make sure everything is ok so far
        expect(verify(issuer.publicKey, attributes, sig)).to.equal(true);

        const fakeKey: string = "fake";
        const fakeNym: Pseudonym = user.createDomainSpecificNym(
            domain,
            fakeKey
        );

        const proof: SignatureProof = user.proveKnowledgeOfSignatureAndNym(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs,
            fakeNym,
            keyIdx
        );

        expect(
            verifier.checkSignatureProofAndNym(
                proof,
                issuer.publicKey,
                showAttributes,
                nym,
                keyIdx
            )
        ).to.equal(false);
    });

    it("should throw an error trying to prove knowledge of a pseudonym with a public key", () => {
        // just to make sure everything is ok so far
        expect(verify(issuer.publicKey, attributes, sig)).to.equal(true);

        const wrongKeyIdx: number = 0;

        expect(() =>
            user.proveKnowledgeOfSignatureAndNym(
                sig,
                issuer.publicKey,
                attributes,
                hiddenSetIdxs,
                nym,
                wrongKeyIdx
            )
        ).to.throw("keyIndex");
    });

    it("should reject when passing the wrong key index when verifying the proof", () => {
        // just to make sure everything is ok so far
        expect(verify(issuer.publicKey, attributes, sig)).to.equal(true);

        const proof: SignatureProof = user.proveKnowledgeOfSignatureAndNym(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs,
            nym,
            keyIdx
        );

        const wrongKeyIdx: number = 1;

        expect(
            verifier.checkSignatureProofAndNym(
                proof,
                issuer.publicKey,
                showAttributes,
                nym,
                wrongKeyIdx
            )
        ).to.equal(false);
    });

    it("should throw an error when passing the wrong key index when verifying the proof", () => {
        // just to make sure everything is ok so far
        expect(verify(issuer.publicKey, attributes, sig)).to.equal(true);

        const proof: SignatureProof = user.proveKnowledgeOfSignatureAndNym(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs,
            nym,
            keyIdx
        );

        const wrongKeyIdx: number = 3;

        expect(() =>
            verifier.checkSignatureProofAndNym(
                proof,
                issuer.publicKey,
                showAttributes,
                nym,
                wrongKeyIdx
            )
        ).to.throw("keyIndex");
    });
});
