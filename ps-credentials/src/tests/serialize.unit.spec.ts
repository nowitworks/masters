/// <reference path="../mcl.d.ts"/>

"use strict";
import {
    Commitment,
    Issuer,
    KeyPair,
    PublicKey,
    ProofOfKnowledge,
    SecretKey,
    Signature,
    SignatureProof,
    randomFr,
    setup
} from "../index";
import { expect } from "chai";
import "mocha";
import * as mcl from "mcl-wasm";

describe("Unit tests for serialization", () => {
    const r: number = 3;
    let keyPair: KeyPair;

    before(async () => {
        await setup();

        keyPair = new KeyPair(r);
    });

    it("should correctly deserialize a serialized PublicKey", () => {
        const originalPublicKey: PublicKey = keyPair.publicKey;
        const serializedPublicKey: string = originalPublicKey.serialize();
        const deserializedPublicKey: PublicKey = PublicKey.deserialize(
            serializedPublicKey
        );

        // let's compare the public keys
        expect(originalPublicKey.g.isEqual(deserializedPublicKey.g)).to.be.true;
        originalPublicKey.Ys.forEach((Yi, idx) => {
            expect(Yi.isEqual(deserializedPublicKey.Ys[idx])).to.be.true;
        });
        expect(originalPublicKey.gt.isEqual(deserializedPublicKey.gt)).to.be
            .true;
        expect(originalPublicKey.Xt.isEqual(deserializedPublicKey.Xt)).to.be
            .true;
        originalPublicKey.Yts.forEach((Yti, idx) => {
            expect(Yti.isEqual(deserializedPublicKey.Yts[idx])).to.be.true;
        });
    });

    it("should correctly deserialize a serialized SecretKey", () => {
        const originalSecretKey: SecretKey = keyPair.secretKey;
        const serializedSecretKey: string = originalSecretKey.serialize();
        const deserializedSecretKey: SecretKey = SecretKey.deserialize(
            serializedSecretKey
        );

        // let's compare the secret keys
        expect(originalSecretKey.X.isEqual(deserializedSecretKey.X)).to.be.true;
    });

    it("should correctly deserialize a serialized KeyPair", () => {
        const serializedKeyPair: string = keyPair.serialize();
        const deserializedKeyPair: KeyPair = KeyPair.deserialize(
            serializedKeyPair
        );

        // let's compare the public keys
        expect(keyPair.publicKey.g.isEqual(deserializedKeyPair.publicKey.g)).to
            .be.true;
        keyPair.publicKey.Ys.forEach((Yi, idx) => {
            expect(Yi.isEqual(deserializedKeyPair.publicKey.Ys[idx])).to.be
                .true;
        });
        expect(keyPair.publicKey.gt.isEqual(deserializedKeyPair.publicKey.gt))
            .to.be.true;
        expect(keyPair.publicKey.Xt.isEqual(deserializedKeyPair.publicKey.Xt))
            .to.be.true;
        keyPair.publicKey.Yts.forEach((Yti, idx) => {
            expect(Yti.isEqual(deserializedKeyPair.publicKey.Yts[idx])).to.be
                .true;
        });

        // let's compare the secret keys
        expect(keyPair.secretKey.X.isEqual(deserializedKeyPair.secretKey.X)).to
            .be.true;
    });

    it("should correctly save a serialized KeyPair to a file and retrieve it", () => {
        const fs = require("fs");
        const filePath: string = "keys.json";

        keyPair.saveToFile(filePath);
        const retrievedKeyPair: KeyPair = KeyPair.loadFromFile(r, filePath);

        // let's compare the public keys
        expect(keyPair.publicKey.g.isEqual(retrievedKeyPair.publicKey.g)).to.be
            .true;
        keyPair.publicKey.Ys.forEach((Yi, idx) => {
            expect(Yi.isEqual(retrievedKeyPair.publicKey.Ys[idx])).to.be.true;
        });
        expect(keyPair.publicKey.gt.isEqual(retrievedKeyPair.publicKey.gt)).to
            .be.true;
        expect(keyPair.publicKey.Xt.isEqual(retrievedKeyPair.publicKey.Xt)).to
            .be.true;
        keyPair.publicKey.Yts.forEach((Yti, idx) => {
            expect(Yti.isEqual(retrievedKeyPair.publicKey.Yts[idx])).to.be.true;
        });

        // let's compare the secret keys
        expect(keyPair.secretKey.X.isEqual(retrievedKeyPair.secretKey.X)).to.be
            .true;

        fs.unlinkSync(filePath);
    });

    it("should correctly create an Issuer, generate its key and save it to a file", () => {
        const fs = require("fs");
        const filePath: string = "keys.json";

        expect(fs.existsSync(filePath)).to.be.false;
        
        const issuer: Issuer = new Issuer(r, filePath);

        expect(fs.existsSync(filePath)).to.be.true;

        fs.unlinkSync(filePath);
    });

    function compareProofsOfKnowledge(
        p1: ProofOfKnowledge,
        p2: ProofOfKnowledge
    ): boolean {
        return (
            p1.challenge.isEqual(p2.challenge) &&
            p1.s.isEqual(p2.s) &&
            p1.sis
                .map((si, idx) => si.isEqual(p2.sis[idx]))
                .reduce((acc, curVal) => acc && curVal)
        );
    }

    it("should correctly deserialize a serialized ProofOfKnowledge", () => {
        const challenge: mcl.Fr = randomFr();
        const s: mcl.Fr = randomFr();
        const sis: mcl.Fr[] = [randomFr(), randomFr(), randomFr()];

        const proof: ProofOfKnowledge = new ProofOfKnowledge(challenge, s, sis);
        const testProof: ProofOfKnowledge = ProofOfKnowledge.deserialize(
            proof.serialize()
        );

        // let's compare the proofs
        expect(compareProofsOfKnowledge(proof, testProof)).to.be.true;
    });

    it("should correctly deserialize a serialized Commitment", () => {
        const challenge: mcl.Fr = randomFr();
        const s: mcl.Fr = randomFr();
        const sis: mcl.Fr[] = [randomFr(), randomFr(), randomFr()];
        const C: mcl.G1 = mcl.hashAndMapToG1("gg");

        const proof: ProofOfKnowledge = new ProofOfKnowledge(challenge, s, sis);
        const commitment: Commitment = new Commitment(C, proof);
        const testCommitment: Commitment = Commitment.deserialize(
            commitment.serialize()
        );

        // let's compare the commitments
        expect(commitment.C.isEqual(testCommitment.C)).to.be.true;
        expect(compareProofsOfKnowledge(commitment.proof, testCommitment.proof))
            .to.be.true;
    });

    it("should correctly deserialize a serialized Signature", () => {
        const sigma1: mcl.G1 = mcl.hashAndMapToG1("sigma1");
        const sigma2: mcl.G1 = mcl.hashAndMapToG1("sigma2");
        const sig: Signature = new Signature(sigma1, sigma2);
        const testSig: Signature = Signature.deserialize(sig.serialize());

        // let's compare the signatures
        expect(sig.sigma1.isEqual(testSig.sigma1)).to.be.true;
        expect(sig.sigma2.isEqual(testSig.sigma2)).to.be.true;
    });

    it("should correctly deserialize a serialized SignatureProof", () => {
        const challenge: mcl.Fr = randomFr();
        const s: mcl.Fr = randomFr();
        const sis: mcl.Fr[] = [randomFr(), randomFr(), randomFr()];
        const proof: ProofOfKnowledge = new ProofOfKnowledge(challenge, s, sis);

        const sigma1: mcl.G1 = mcl.hashAndMapToG1("sigma1");
        const sigma2: mcl.G1 = mcl.hashAndMapToG1("sigma2");
        const sig: Signature = new Signature(sigma1, sigma2);

        const sigProof: SignatureProof = new SignatureProof(proof, sig);
        const testSigProof: SignatureProof = SignatureProof.deserialize(
            sigProof.serialize()
        );

        // let's compare the signature proofs
        //    let's compare the proofs
        expect(compareProofsOfKnowledge(sigProof.proof, testSigProof.proof)).to.be.true;

        //    let's compare the signatures
        expect(sigProof.sigmaPrime.sigma1.isEqual(testSigProof.sigmaPrime.sigma1)).to.be.true;
        expect(testSigProof.sigmaPrime.sigma2.isEqual(testSigProof.sigmaPrime.sigma2)).to.be.true;
    });
});
