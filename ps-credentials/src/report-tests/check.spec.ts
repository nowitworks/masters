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

describe("CHECK", () => {
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
    let proof: SignatureProof;
    let proofNym: SignatureProof;

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

        
        proof = user.proveKnowledgeOfSignature(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs
        );

        proofNym = user.proveKnowledgeOfSignatureAndNym(
            sig,
            issuer.publicKey,
            attributes,
            hiddenSetIdxs,
            nym,
            keyIdx
        );
    });

    it("should *accept* the showing of a valid signature", () => {
        
        expect(
            verifier.checkSignatureProof(
                proof,
                issuer.publicKey,
                showAttributes
            )
        ).to.equal(true);
    });

    it("should *accept* the showing of a valid signature and pseudonym", () => {
        
        expect(
            verifier.checkSignatureProofAndNym(
                proofNym,
                issuer.publicKey,
                showAttributes,
                nym,
                keyIdx
            )
        ).to.equal(true);
    });
});
