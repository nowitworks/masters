"use strict";
import mcl = require("mcl-wasm");
import {
    createChallenge,
    generateRandomizers,
    getCredentialCandidateW,
    getCredentialRandomizersCommitment,
    getNymCandidateW,
    getNymRandomizerCommitment,
    getProofExponents,
    randomizeSignature
} from "./ps-internal";
import {
    Commitment,
    KeyPair,
    ProofOfKnowledge,
    Pseudonym,
    PublicKey,
    SecretKey,
    Signature,
    SignatureProof,
    randomFr
} from "./ps-types";

/**
 * js implementation of PS credential scheme - Short Randomizable Signatures
 * by Pointcheval and Sanders 2016
 * https://eprint.iacr.org/2015/525.pdf
 */

/**
 * The issuer of credentials.
 */
export class Issuer {
    /** The total number of attributes the credential carries. */
    public r: number;

    public publicKey: PublicKey;
    private secretKey: SecretKey;

    /**
     * Creates an Issuer instance.
     * @param r  The total number of attributes the credential carries.
     * @param filepath  The location of the file with the [[KeyPair]] for
     * the [[Issuer]]. If the file does not exist, it is created and a newly
     * generated [[KeyPair]] is saved to the file.
     */
    public constructor(r: number, filepath?: string) {
        this.r = r;

        let keyPair: KeyPair;

        if (filepath !== undefined) {
            keyPair = KeyPair.loadFromFile(r, filepath);
        } else {
            keyPair = new KeyPair(r);
        }

        this.publicKey = keyPair.publicKey;
        this.secretKey = keyPair.secretKey;
    }

    /**
     * Blindly signs the user's committed attributes. This corresponds to issuing the blind credential.
     * This signature is then unblinded by the [[User]] and becomes ready to use.
     * @param commitment  The user's commitment on the user defined attributes.
     * @param issuerAttrs  The issuer defined attributes.
     * @returns The blind signature of the user's attributes.
     */
    public blindSign(commitment: Commitment, issuerAttrs: string[]): Signature {
        if (!this.checkCommitment(commitment, issuerAttrs)) {
            throw new Error(
                "Issuer: Could not issue credential - the commitment on the attributes is not valid."
            );
        }

        const hashedAttributes: mcl.Fr[] = issuerAttrs.map(mcl.hashToFr);

        const u: mcl.Fr = randomFr();
        return new Signature(
            // sigma1 = g*u
            mcl.mul(this.publicKey.g, u),
            // sigma2 = (X + C + sum(Yj*mj))*u, where mj are the issuer defined attributes
            // note that we only use the last part of the array of Ys of the public key
            mcl.mul(
                mcl.add(
                    mcl.add(this.secretKey.X, commitment.C),
                    issuerAttrs.length === 0 // in case there are no issuer defined attributes
                        ? new mcl.G1()
                        : this.publicKey.Ys.slice(this.r - issuerAttrs.length)
                              .map((Yi, idx) =>
                                  mcl.mul(Yi, hashedAttributes[idx])
                              )
                              .reduce(mcl.add)
                ),
                u
            )
        );
    }

    /**
     * Checks the validity of the proof of knowledge on the commitment.
     * @param commitment  The user's commitment on the attributes and its proof.
     * @param issuerAttrs  The issuer defined attributes.
     * @returns The validity of the commitment.
     */
    private checkCommitment(
        commitment: Commitment,
        issuerAttrs: string[]
    ): boolean {
        // the size of array sis from commitment must be equal to the number of user defined attributes
        if (commitment.proof.sis.length !== this.r - issuerAttrs.length) {
            throw new Error(
                "Issuer: Number of values in commitment does not correspond to the number of user defined attributes"
            );
        }

        // candidate W, W' = g*s + sum(Yi*si) - C*c
        // note that we only use part of the public key's values of Y (depending on the size of array sis)
        const Wprime: mcl.G1 = mcl.sub(
            mcl.add(
                mcl.mul(this.publicKey.g, commitment.proof.s),
                commitment.proof.sis
                    .map((si, idx) => mcl.mul(this.publicKey.Ys[idx], si))
                    .reduce(mcl.add)
            ),
            mcl.mul(commitment.C, commitment.proof.challenge)
        );

        // candidate challenge, c' = H(C||g||Y1||...||Yr||W')
        const cPrime: mcl.Fr = createChallenge(
            commitment.C,
            this.publicKey.g,
            ...this.publicKey.Ys, // TODO: add only the used part of the array
            Wprime
        );

        // accept if c == c'
        return commitment.proof.challenge.isEqual(cPrime);
    }
}

/**
 * The user. Credentials are issued to the user. The user can also show a credential.
 */
export class User {
    /** The random value used to create a commitment */
    private t: mcl.Fr;

    // TODO: consider having attributes (user and issuer defined) as class properties

    /**
     * Creates a commitment on the attributes the user wishes to have signed
     * @param publicKey  The [[Issuer]]'s public key.
     * @param attributes  The secret attributes that the user wants signed.
     * @returns The commitment on the attributes
     */
    public createCommitment(
        publicKey: PublicKey,
        attributes: string[]
    ): Commitment {
        this.t = randomFr();
        const hashedAttributes: mcl.Fr[] = attributes.map(mcl.hashToFr);

        // C = g*t + sum(Yi*mi)
        // note that we only use as many values of Y (from the public key) as there are attributes
        const C: mcl.G1 = mcl.add(
            mcl.mul(publicKey.g, this.t),
            hashedAttributes
                .map((attri, idx) => mcl.mul(publicKey.Ys[idx], attri))
                .reduce(mcl.add)
        );
        return new Commitment(
            C,
            this.createProofOfCommitment(C, publicKey, attributes)
        );
    }

    /**
     * Creates a valid signature from the blind signature received from the [[Issuer]].
     * @param publicKey  The [[Issuer]]'s public key.
     * @param blindSig  The blind signature created by the [[Issuer]].
     * @returns Valid unblinded signature on all attributes (user and issuer defined).
     */
    public unblindSignature(blindSig: Signature): Signature {
        return new Signature(
            blindSig.sigma1,
            mcl.sub(blindSig.sigma2, mcl.mul(blindSig.sigma1, this.t))
        );
    }

    /**
     * Creates a proof of knowledge of a signature issued by the [[Issuer]] over all
     * the attributes. This proof does not disclose the hidden attributes.
     * @param sig  The signature.
     * @param publicKey  The [[Issuer]]'s public key.
     * @param attributes  All the user's attributes.
     * @param hiddenSetIdxs  The indexes of the attributes the user wants to hide.
     * @returns The proof of knowledge of the signature and the auxiliary signature.
     */
    public proveKnowledgeOfSignature(
        sig: Signature,
        publicKey: PublicKey,
        attributes: string[],
        hiddenSetIdxs: number[]
    ): SignatureProof {
        const [sigmaPrime, v]: [Signature, mcl.Fr] = randomizeSignature(sig);

        return new SignatureProof(
            this.createProofOfKnowledgeOfSignature(
                sigmaPrime,
                publicKey,
                attributes,
                hiddenSetIdxs,
                v
            ),
            sigmaPrime
        );
    }

    /**
     * Creates a proof of knowledge of a signature issued by the [[Issuer]] over all
     * the attributes. This proof does not disclose the hidden attributes. This proof
     * also proves the correctness of a public pseudonym.
     * @param sig  The signature.
     * @param publicKey  The [[Issuer]]'s public key.
     * @param attributes  All the user's attributes.
     * @param hiddenSetIdxs  The indexes of the attributes the user wants to hide.
     * @param nym  The pseudonym - it is of the form nym = H(domain)^x, where x is
     * a secret attribute of the user.
     * @param keyIdx  The index of the attribute used to compute the pseudonym.
     * @returns The proof of knowledge of the signature and the auxiliary signature.
     */
    public proveKnowledgeOfSignatureAndNym(
        sig: Signature,
        publicKey: PublicKey,
        attributes: string[],
        hiddenSetIdxs: number[],
        nym: Pseudonym,
        keyIdx: number
    ): SignatureProof {
        const [sigmaPrime, v]: [Signature, mcl.Fr] = randomizeSignature(sig);

        return new SignatureProof(
            this.createProofOfKnowledgeOfSignatureAndNym(
                sigmaPrime,
                publicKey,
                attributes,
                hiddenSetIdxs,
                v,
                nym,
                keyIdx
            ),
            sigmaPrime
        );
    }

    /**
     * Creates a domain-specific pseudonym. nym = H(domain)^x, where x is
     * a secret key.
     * @param domain  The domain.
     * @param keyStr  The attribute representig the key. TODO: force minimum
     * size of this string to ensure security.
     * @returns The domain-specific pseudonym.
     */
    public createDomainSpecificNym(domain: string, keyStr: string): Pseudonym {
        const nym: mcl.G1 = mcl.mul(
            mcl.hashAndMapToG1(domain),
            mcl.hashToFr(keyStr)
        );

        return new Pseudonym(domain, nym);
    }

    /**
     * Creates a proof of knowledge of the commitment on the attributes.
     * @param C  The commitment.
     * @param publicKey  The [[Issuer]]'s public key.
     * @param attributes  The attributes that the user wants signed.
     * @returns The proof of knowledge of the commitment.
     */
    private createProofOfCommitment(
        C: mcl.G1,
        publicKey: PublicKey,
        attributes: string[]
    ): ProofOfKnowledge {
        // pick random w, w1, ..., wr \in Fr
        const w: mcl.Fr = randomFr();
        const wis: mcl.Fr[] = Array(attributes.length)
            .fill(1)
            .map(randomFr);

        // commitment on the random values
        // W = g*w + sum(Yi*wi)
        // note that we only use as many values of Y (from the public key) as there are attributes
        const W: mcl.G1 = mcl.add(
            mcl.mul(publicKey.g, w),
            wis.map((wi, idx) => mcl.mul(publicKey.Ys[idx], wi)).reduce(mcl.add)
        );

        // c = H(C||g||Y1||...||Yr||W)
        const c: mcl.Fr = createChallenge(C, publicKey.g, ...publicKey.Ys, W);

        const hashedAttributes: mcl.Fr[] = attributes.map(mcl.hashToFr);

        // s = w + c*t
        const s: mcl.Fr = mcl.add(w, mcl.mul(c, this.t));

        // s1 = w1 + c*m1
        // ...
        // sr = wr + c*mr
        const sis: mcl.Fr[] = wis.map((wi, idx) =>
            mcl.add(wi, mcl.mul(c, hashedAttributes[idx]))
        );

        return new ProofOfKnowledge(c, s, sis);
    }

    /**
     * Creates a proof of knowledge of a signature.
     * @param sig  The signature.
     * @param publicKey  The [[Issuer]]'s public key.
     * @param attributes  All the user's attributes.
     * @param hiddenSetIdxs  The indexes of the attributes the user wants to hide.
     * @param v  Random value used to enable unlinkability.
     * @returns The proof of knowledge of the signature.
     */
    private createProofOfKnowledgeOfSignature(
        sig: Signature,
        publicKey: PublicKey,
        attributes: string[],
        hiddenSetIdxs: number[],
        v: mcl.Fr
    ): ProofOfKnowledge {
        /**
         * hiddenSetIdxs, referred to as H, is the set of indexes of the hidden attributes
         * D is the set of indexes of the disclosed attributes
         *
         * Here is the proof we want to instantiate
         * PK{ (v, m1, ..., mr): e(sigma1, Xt) * PROD_in_H(e(sigma1,Yti)^m_i)
         *                             * PROD_in_D(e(sigma1,Yti)^m_i) * e(sigma1, gt)^v = e(sigma2, gt) }
         *
         * we can re-write it as
         * PK{ (v, m1, ..., mr): e(sigma2, gt)/( e(sigma1, Xt) * PROD_in_D(e(sigma1,Yti)^m_i) )
         *                                                = e(sigma1, gt)^v * PROD_in_H(e(sigma1,Yti)^mi) }
         */

        // pick random w, wi \in Fr, for i \in H
        const randomizers: mcl.Fr[] = generateRandomizers(
            hiddenSetIdxs.length + 1
        );

        // commitment on the random values
        // W = e(sigma1, gt)^w * PROD_in_H(e(sigma1,Yti)^wi)
        // but we want to move the exponents inside the pairing, so we get
        // W = e(sigma1*w, gt) * PROD_in_H(e(sigma1*wi,Yti))
        const W: mcl.GT = getCredentialRandomizersCommitment(
            sig,
            publicKey,
            randomizers,
            hiddenSetIdxs
        );

        // c = H(gt||Xt||sigma1||sigma2||Yt1||...||Ytr||W)
        const c: mcl.Fr = createChallenge(
            publicKey.gt,
            publicKey.Xt,
            sig.sigma1,
            sig.sigma2,
            ...publicKey.Yts, // TODO: only add used Ys
            W
        );

        const hashedAttrs: mcl.Fr[] = hiddenSetIdxs.map(hiddenIdx =>
            mcl.hashToFr(attributes[hiddenIdx])
        );

        const exponents: mcl.Fr[] = getProofExponents(
            c,
            randomizers,
            [v].concat(hashedAttrs)
        );

        // s = w + c*v
        const s: mcl.Fr = exponents[0];

        // si = wi + c*mi, for i \in H
        const sis: mcl.Fr[] = exponents.slice(1);

        return new ProofOfKnowledge(c, s, sis);
    }

    /**
     * Creates a proof of knowledge of a signature and of the correctness of a
     * public domain-specific pseudonym.
     * @param sig  The signature.
     * @param publicKey  The [[Issuer]]'s public key.
     * @param attributes  All the user's attributes.
     * @param hiddenSetIdxs  The indexes of the attributes the user wants to hide.
     * @param v  Random value used to enable unlinkability.
     * @param nym  The domain-specific pseudonym.
     * @param keyIdx  The index of the attribute used as a key to create the pseudonym. This
     * index should be in respect to the array with all the attributes.
     * @returns The proof of knowledge.
     */
    private createProofOfKnowledgeOfSignatureAndNym(
        sig: Signature,
        publicKey: PublicKey,
        attributes: string[],
        hiddenSetIdxs: number[],
        v: mcl.Fr,
        nym: Pseudonym,
        keyIdx: number
    ): ProofOfKnowledge {
        // pick random w, wi \in Fr, for i \in H
        const randomizers: mcl.Fr[] = generateRandomizers(
            hiddenSetIdxs.length + 1
        );

        // commitment on the random values
        // W1 is W from the signature proof
        const W1: mcl.GT = getCredentialRandomizersCommitment(
            sig,
            publicKey,
            randomizers,
            hiddenSetIdxs
        );

        if (hiddenSetIdxs.indexOf(keyIdx) === -1) {
            throw new Error(
                "keyIndex is not valid - it does not correspond to a hidden attribute"
            );
        }

        // W2 is the commitment on the randomizer for the pseudonym
        const W2: mcl.G1 = getNymRandomizerCommitment(
            nym.domain,
            randomizers[hiddenSetIdxs.indexOf(keyIdx) + 1]
        );

        // c = H(gt||Xt||sigma1||sigma2||Yt1||...||Ytr||W1||nym||domain||W2)
        const c: mcl.Fr = createChallenge(
            publicKey.gt,
            publicKey.Xt,
            sig.sigma1,
            sig.sigma2,
            ...publicKey.Yts, // TODO: only add used Ys
            W1,
            nym.nym,
            mcl.hashAndMapToG1(nym.domain),
            W2
        );

        const hashedAttrs: mcl.Fr[] = hiddenSetIdxs.map(hiddenIdx =>
            mcl.hashToFr(attributes[hiddenIdx])
        );

        const exponents: mcl.Fr[] = getProofExponents(
            c,
            randomizers,
            [v].concat(hashedAttrs)
        );

        // s = w + c*v
        const s: mcl.Fr = exponents[0];

        // si = wi + c*mi, for i \in H
        const sis: mcl.Fr[] = exponents.slice(1);

        return new ProofOfKnowledge(c, s, sis);
    }
}

/**
 * The entity that verifies a credential shown by the user.
 */
export class Verifier {
    /**
     * Checks the validity of a proof of knowledge of a signature.
     * @param signatureProof  The signature proof of knowledge and the auxiliary signature.
     * @param publicKey  The [[Issuer]]'s public key.
     * @param attributes  An array with the attributes the [[User]] wishes to disclose. The
     * array should be of size r and contain `undefined` entries in the positions of the
     * attributes the user wishes to hide.
     * @returns The validity of the proof.
     */
    public checkSignatureProof(
        signatureProof: SignatureProof,
        publicKey: PublicKey,
        attributes: string[]
    ): boolean {
        if (attributes.length !== publicKey.Ys.length) {
            throw new Error(
                "number of attributes does not match with public key parameters"
            );
        }

        const hiddenSetIdxs: number[] = attributes
            .map((_, idx) => idx)
            .filter((_, idx) => attributes[idx] === null);
        const disclosureSetIdxs: number[] = attributes
            .map((_, idx) => idx)
            .filter((_, idx) => attributes[idx] !== null);

        const hashedDisclosedAttributes: mcl.Fr[] = disclosureSetIdxs.map(el =>
            mcl.hashToFr(attributes[el])
        );

        // prodInH = PROD_in_H(e(sigma1*si, Yti))
        // prodInD = PROD_in_D(e(sigma1*m_i, Yti))
        // candidate W, W' = e(sigma1,gt)^s * prodInH / ( e(sigma2, gt)/(e(sigma1, Xt) * prodInD) )^c
        // but we want to move the exponent inside the pairing for better performance, so we get
        // W' = e(sigma1*s,gt) * prodInH / ( e(sigma2, gt)/(e(sigma1, Xt) * prodInD) )^c
        const Wprime: mcl.GT = getCredentialCandidateW(
            signatureProof.sigmaPrime,
            [signatureProof.proof.s].concat(signatureProof.proof.sis),
            signatureProof.proof.challenge,
            publicKey,
            hiddenSetIdxs,
            disclosureSetIdxs,
            hashedDisclosedAttributes
        );

        // candidate c, c' = H(gt||Xt||sigma1||sigma2||Yt1||...||Ytr||W')
        const cPrime: mcl.Fr = createChallenge(
            publicKey.gt,
            publicKey.Xt,
            signatureProof.sigmaPrime.sigma1,
            signatureProof.sigmaPrime.sigma2,
            ...publicKey.Yts, // TODO: only add used Ys
            Wprime
        );

        // accept if c == c'
        return signatureProof.proof.challenge.isEqual(cPrime);
    }

    /**
     * Checks the validity of a proof of knowledge of a signature and correctness of pseudonym.
     * @param signatureProof  The signature proof of knowledge and the auxiliary signature.
     * @param publicKey  The [[Issuer]]'s public key.
     * @param attributes  An array with the attributes the [[User]] wishes to disclose. The
     * array should be of size r and contain `undefined` entries in the positions of the
     * attributes the user wishes to hide.
     * @param nym  The domain-specific pseudonym.
     * @param keyIdx  The index of the attribute used as a key to create the pseudonym. This
     * index should be in respect to the array with all the attributes.
     * @returns The validity of the proof.
     */
    public checkSignatureProofAndNym(
        signatureProof: SignatureProof,
        publicKey: PublicKey,
        attributes: string[],
        nym: Pseudonym,
        keyIdx: number
    ): boolean {
        if (attributes.length !== publicKey.Ys.length) {
            throw new Error(
                "number of attributes does not match with public key parameters"
            );
        }

        const hiddenSetIdxs: number[] = attributes
            .map((_, idx) => idx)
            .filter((_, idx) => attributes[idx] === null);
        const disclosureSetIdxs: number[] = attributes
            .map((_, idx) => idx)
            .filter((_, idx) => attributes[idx] !== null);

        const hashedDisclosedAttributes: mcl.Fr[] = disclosureSetIdxs.map(el =>
            mcl.hashToFr(attributes[el])
        );

        if (hiddenSetIdxs.indexOf(keyIdx) === -1) {
            throw new Error(
                "keyIndex is not valid - it does not correspond to a hidden attribute"
            );
        }

        // prodInH = PROD_in_H(e(sigma1*si, Yti))
        // prodInD = PROD_in_D(e(sigma1*m_i, Yti))
        // candidate W1, W1' = e(sigma1,gt)^s * prodInH / ( e(sigma2, gt)/(e(sigma1, Xt) * prodInD) )^c
        // but we want to move the exponent inside the pairing for better performance, so we get
        // W1' = e(sigma1*s,gt) * prodInH / ( e(sigma2, gt)/(e(sigma1, Xt) * prodInD) )^c
        const W1prime: mcl.GT = getCredentialCandidateW(
            signatureProof.sigmaPrime,
            [signatureProof.proof.s].concat(signatureProof.proof.sis),
            signatureProof.proof.challenge,
            publicKey,
            hiddenSetIdxs,
            disclosureSetIdxs,
            hashedDisclosedAttributes
        );

        const W2prime: mcl.G1 = getNymCandidateW(
            nym,
            signatureProof.proof.sis[hiddenSetIdxs.indexOf(keyIdx)],
            signatureProof.proof.challenge
        );

        // candidate c, c' = H(gt||Xt||sigma1||sigma2||Yt1||...||Ytr||W1'||nym||domain||W2')
        const cPrime: mcl.Fr = createChallenge(
            publicKey.gt,
            publicKey.Xt,
            signatureProof.sigmaPrime.sigma1,
            signatureProof.sigmaPrime.sigma2,
            ...publicKey.Yts, // TODO: only add used Ys
            W1prime,
            nym.nym,
            mcl.hashAndMapToG1(nym.domain),
            W2prime
        );

        // accept if c == c'
        return signatureProof.proof.challenge.isEqual(cPrime);
    }
}
