"use strict";
import mcl = require("mcl-wasm");

import {
    Pseudonym,
    PublicKey,
    Signature,
    SignatureProof,
    randomFr
} from "./ps-types";

/**
 * `ps-internal` is a module for advanced users who want to extend the zero-knowledge
 * proofs from the credential library. This could be used to add more statements to
 * the proof that use some of the secrets included in the credential.
 *
 * :warning: Use with care and only if you know what you are doing.
 */

// ----------------------------- Randomizers -----------------------------

/**
 * Generates the necessary number of randomizers to create a non-interactive zero
 * knowledge proof.
 * @param numOfSecrets  The number of secrets the proof aims to prove knowledge
 * of. This is also the number of randomizers the function will output.
 * @returns The randomizers to create the proof.
 */
export function generateRandomizers(numOfSecrets: number): mcl.Fr[] {
    return Array(numOfSecrets)
        .fill(1)
        .map(randomFr);
}

// ---------------------- Commitment on Randomizers ----------------------

/**
 * Creates the commitment on the randomizers for the proof of knowledge
 * of a credential.
 * @param sig  The signature (which represents the credential).
 * @param publicKey  The [[Issuer]]'s public key.
 * @param w  Randomizer for value v (used for providing unlinkability).
 * @param wis  Array of randomizers for attributes.
 * @param hiddenSetIdxs  The indexes of the hidden attributes.
 * @returns The commitment on the randomizers
 */
export function getCredentialRandomizersCommitment(
    sig: Signature,
    publicKey: PublicKey,
    randomizers: mcl.Fr[],
    hiddenSetIdxs: number[]
): mcl.GT {
    const w: mcl.Fr = randomizers[0];
    const wis: mcl.Fr[] = randomizers.slice(1);

    // commitment on the random values
    // W = e(sigma1, gt)^w * PROD_in_H(e(sigma1,Yti)^wi)
    // but we want to move the exponents inside the pairing, so we get
    // W = e(sigma1*w, gt) * PROD_in_H(e(sigma1*wi,Yti))
    return mcl.mul(
        mcl.pairing(mcl.mul(sig.sigma1, w), publicKey.gt),
        hiddenSetIdxs
            .map((globalIdx, localIdx) =>
                mcl.pairing(
                    mcl.mul(sig.sigma1, wis[localIdx]),
                    publicKey.Yts[globalIdx]
                )
            )
            .reduce(mcl.mul)
    );
}

/**
 * Creates the commitment on the randomizers for the proof of knowledge
 * of a domain specific pseudonym.
 * @param domain  The domain for which the pseudonym refers to.
 * @param randomizer  The randomizer for the [[User]]'s key (one of
 * the attributes) from the proof of knowledge.
 * @returns The commitment on the randomizer.
 */
export function getNymRandomizerCommitment(
    domain: string,
    randomizer: mcl.Fr
): mcl.G1 {
    // commitment on the random value
    // W = H(domain)^randomizer
    return mcl.mul(mcl.hashAndMapToG1(domain), randomizer);
}

// ------------------------------ Challenge ------------------------------

/**
 * To make sure that the elements used to create the challenge are convertible to a string.
 */
interface ChallengeElement {
    getStr(): string;
}

/**
 * Creates a challenge for the proofs of knowledge. It hashes together all
 * the elements in the array into a field element.
 * @param elements  The array containing the elements to hash
 * @return The field element resulting of hashing together all the inputs
 */
export function createChallenge(...elements: ChallengeElement[]): mcl.Fr {
    // TODO: Make this bijective
    const state: string = elements.map(el => el.getStr()).join("|");

    return mcl.hashToFr(state);
}

// ------------------------------ Exponents ------------------------------

/**
 * Computes the exponents for a non-interactive zero knowledge proof (NIZKP). Each
 * exponent is of the form *exponent_i = randomizer_i + challenge*secret_i*.
 * @param challenge  The challenge computed for the NIZKP.
 * @param randomizers  The randomizers
 * @param secrets
 */
export function getProofExponents(
    challenge: mcl.Fr,
    randomizers: mcl.Fr[],
    secrets: mcl.Fr[]
): mcl.Fr[] {
    // exponent_i = randomizer_i + challenge*secret_i
    return secrets.map((secret, idx) =>
        mcl.add(randomizers[idx], mcl.mul(challenge, secret))
    );
}

// ----------------------- Candidate Commitments -------------------------

/**
 * Computes the candidate commitment W, W', for verifying the proof of knowledge.
 * @param signatureProof  The signature proof of knowledge and the auxiliary signature.
 * @param publicKey  The [[Issuer]]'s public key.
 * @param hiddenSetIdxs  The indexes of the attributes the user wants to hide.
 * @param disclosureSetIdxs  The indexes of the attributes the user wants to disclose.
 * @param hashedDisclosedAttributes  The hash of the attributes the user wants to disclose.
 * @returns The value of the candidate commitment.
 */
export function getCredentialCandidateW(
    signature: Signature,
    responses: mcl.Fr[],
    challenge: mcl.Fr,
    publicKey: PublicKey,
    hiddenSetIdxs: number[],
    disclosureSetIdxs: number[],
    hashedDisclosedAttributes: mcl.Fr[]
): mcl.GT {
    const s: mcl.Fr = responses[0];
    const sis: mcl.Fr[] = responses.slice(1);

    // prodInH = PROD_in_H(e(sigma1*si, Yti))
    const prodInH: mcl.GT = hiddenSetIdxs
        .map((globalIdx, localIdx) =>
            mcl.pairing(
                mcl.mul(signature.sigma1, sis[localIdx]),
                publicKey.Yts[globalIdx]
            )
        )
        .reduce(mcl.mul);

    let prodInD: mcl.GT;
    if (disclosureSetIdxs.length === 0) {
        prodInD = null;
    } else {
        // prodInD = PROD_in_D(e(sigma1*m_i, Yti))
        prodInD = disclosureSetIdxs
            .map((globalIdx, localIdx) =>
                mcl.pairing(
                    mcl.mul(
                        signature.sigma1,
                        hashedDisclosedAttributes[localIdx]
                    ),
                    publicKey.Yts[globalIdx]
                )
            )
            .reduce(mcl.mul);
    }

    if (prodInD === null) {
        return mcl.div(
            mcl.mul(
                mcl.pairing(mcl.mul(signature.sigma1, s), publicKey.gt),
                prodInH
            ),
            mcl.pow(
                mcl.div(
                    mcl.pairing(signature.sigma2, publicKey.gt),
                    mcl.pairing(signature.sigma1, publicKey.Xt)
                ),
                challenge
            )
        );
    } else {
        // candidate W, W' = e(sigma1,gt)^s * prodInH / ( e(sigma2, gt)/(e(sigma1, Xt) * prodInD) )^c
        // but we want to move the exponent inside the pairing for better performance, so we get
        // W' = e(sigma1*s,gt) * prodInH / ( e(sigma2, gt)/(e(sigma1, Xt) * prodInD) )^c
        return mcl.div(
            mcl.mul(
                mcl.pairing(mcl.mul(signature.sigma1, s), publicKey.gt),
                prodInH
            ),
            mcl.pow(
                mcl.div(
                    mcl.pairing(signature.sigma2, publicKey.gt),
                    mcl.mul(
                        mcl.pairing(signature.sigma1, publicKey.Xt),
                        prodInD
                    )
                ),
                challenge
            )
        );
    }
}

/**
 * Computes the candidate commitment W, W', for verifying the proof of knowledge of
 * the pseudonym.
 * @param nym  The domain-specific pseudonym.
 * @param response  The value from the proof of knowledge used to recompute the commitment.
 * @param challenge  The challenge from the proof of knowledge.
 * @returns The value of the candidate commitment.
 */
export function getNymCandidateW(
    nym: Pseudonym,
    response: mcl.Fr,
    challenge: mcl.Fr
): mcl.G1 {
    // W = H(domain)*w
    // so W' = H(domain)*response - nym*c
    // where response = w + c*x and nym = H(domain)*x
    return mcl.sub(
        mcl.mul(mcl.hashAndMapToG1(nym.domain), response),
        mcl.mul(nym.nym, challenge)
    );
}

// ------------------------- Randomize Signature -------------------------

/**
 * Randomizes a signature allowing for it to be used unlinkably. Also returns
 * the randomizer necessary to prove knowledge of the signature (i.e. for use
 * in ZKPs).
 * @param sig  The signature.
 * @returns Tuple containing the randomized signature and the ZKP randomizer.
 */
export function randomizeSignature(sig: Signature): [Signature, mcl.Fr] {
    const u: mcl.Fr = randomFr();
    const v: mcl.Fr = randomFr();

    // sigmaPrime = (sigma1*u, (sigma2+sigma1*v)*u)
    const sigmaPrime: Signature = new Signature(
        mcl.mul(sig.sigma1, u),
        mcl.mul(mcl.add(sig.sigma2, mcl.mul(sig.sigma1, v)), u)
    );

    return [sigmaPrime, v];
}
