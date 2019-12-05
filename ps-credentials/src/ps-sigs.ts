"use strict";
import mcl = require("mcl-wasm");
import { Serializable, Signature, randomFr } from "./ps-types";

/**
 * js implementation of PS credential scheme - Short Randomizable Signatures
 * by Pointcheval and Sanders 2016
 * https://eprint.iacr.org/2015/525.pdf
 */

// ------ ------ 4.2 A Multi-Message Signature Scheme ------ ------

export class SecretKey {
    public x: mcl.Fr;
    public ys: mcl.Fr[];

    public constructor(r: number) {
        this.x = randomFr();

        this.ys = Array(r)
            .fill(1)
            .map(randomFr);
    }
}

export class PublicKey {
    public gt: mcl.G2;
    public Xt: mcl.G2;
    public Yts: mcl.G2[];

    public constructor(r: number, secretKey: SecretKey) {
        this.gt = mcl.hashAndMapToG2("gtilde");
        this.Xt = mcl.mul(this.gt, secretKey.x);
        this.Yts = secretKey.ys.map(yi => mcl.mul(this.gt, yi));
    }
}

export class KeyPair {
    public publicKey: PublicKey;
    public secretKey: SecretKey;

    public constructor(r: number) {
        this.secretKey = new SecretKey(r);
        this.publicKey = new PublicKey(r, this.secretKey);
    }
}

/**
 * @desc sets up the mcl library
 * @param number: curveType - the curve we want to use (see mcl.d.ts for available curves)
 */
export async function setup(curveType: number = mcl.BN254): Promise<void> {
    await mcl.init(curveType);
}

/**
 * @desc signs an array of messages using the secret key
 * @param SecretKey: secretKey - secret key
 * @param string[]: messages - messages to sign
 * @return Signature: signature
 */
export function sign(secretKey: SecretKey, messages: string[]): Signature {
    const h: mcl.G1 = mcl.hashAndMapToG1("random"); // TODO: make it actually random
    // TODO: check if h.isZero()

    const hashedMessages: mcl.Fr[] = messages.map(msg => mcl.hashToFr(msg));

    const exp: mcl.Fr = mcl.add(
        secretKey.x,
        secretKey.ys
            .map((y, idx) => mcl.mul(y, hashedMessages[idx]))
            .reduce(mcl.add)
    );

    return new Signature(h, mcl.mul(h, exp));
}

/**
 * @desc verifies the signature of an array of messages using the public key
 * @param PublicKey: publicKey - public key
 * @param string[]: messages - messages corresponding to the signature
 * @param Signature: sig - signature over the messages
 * @return boolean: validity of the signature
 */
export function verify(
    publicKey: PublicKey,
    messages: string[],
    sig: Signature
): boolean {
    if (sig.sigma1.isZero()) {
        return false;
    }

    const hashedMessages: mcl.Fr[] = messages.map(msg => mcl.hashToFr(msg));

    const XprodYm: mcl.G2 = mcl.add(
        publicKey.Xt,
        publicKey.Yts.map((Yt, idx) => mcl.mul(Yt, hashedMessages[idx])).reduce(
            mcl.add
        )
    );

    const eLeft: mcl.GT = mcl.pairing(sig.sigma1, XprodYm);
    const eRight: mcl.GT = mcl.pairing(sig.sigma2, publicKey.gt);

    return eLeft.isEqual(eRight);
}

/**
 * @desc randomizes a signature while keeping it valid
 * @param Signature: sig - signature
 * @return Signature: randomized signature
 */
export function randomize(sig: Signature): Signature {
    const t: mcl.Fr = new mcl.Fr();

    do {
        t.setByCSPRNG();
    } while (t.isOne() || t.isZero());

    return new Signature(mcl.mul(sig.sigma1, t), mcl.mul(sig.sigma2, t));
}

export { mcl }; /*THIS IS A HACK - BE CAREFUL*/
