"use strict";
import mcl = require("mcl-wasm");

/**
 * Creates a new random field element (mcl.Fr).
 * @returns  The random field element.
 */
export function randomFr(): mcl.Fr {
    const a: mcl.Fr = new mcl.Fr();
    a.setByCSPRNG();
    return a;
}

/**
 * Interface for classes that should be serializable so that data can be
 * easily transmitted over the network and through the browser.
 */
export interface Serializable {
    /** Transform object into a string representation. */
    serialize: () => string;

    // deserialize: (JSONStr: string) => void;
}

/**
 * A signature over a number of different messages.
 */
export class Signature implements Serializable {
    public constructor(public sigma1: mcl.G1, public sigma2: mcl.G1) {}

    /**
     * Transforms a Signature object into its string representation.
     * @returns String representation of the Signature object.
     */
    public serialize(): string {
        return JSON.stringify({
            sigma1: this.sigma1.serializeToHexStr(),
            sigma2: this.sigma2.serializeToHexStr()
        });
    }

    /**
     * Static method that takes a string representation of a Signature object and reconstructs the
     * original object.
     * @param JSONStr  String representation (in JSON) of a Signature object.
     * @returns The object which the input string represents.
     */
    public static deserialize(JSONStr: string): Signature {
        const toDeserialize = JSON.parse(JSONStr);

        return new Signature(
            mcl.deserializeHexStrToG1(toDeserialize.sigma1),
            mcl.deserializeHexStrToG1(toDeserialize.sigma2)
        );
    }
}

/**
 * The public key used for the [[Issuer]]. Property names are according to the paper.
 */
export class PublicKey implements Serializable {
    public constructor(
        public g: mcl.G1,
        public Ys: mcl.G1[],
        public gt: mcl.G2,
        public Xt: mcl.G2,
        public Yts: mcl.G2[]
    ) {}

    /**
     * Transforms a PublicKey object into its string representation.
     * @returns String representation of the PublicKey object.
     */
    public serialize(): string {
        return JSON.stringify({
            g: this.g.serializeToHexStr(),
            Ys: this.Ys.map(Yi => Yi.serializeToHexStr()),
            gt: this.gt.serializeToHexStr(),
            Xt: this.Xt.serializeToHexStr(),
            Yts: this.Yts.map(Yti => Yti.serializeToHexStr())
        });
    }

    /**
     * Static method that takes a string representation of a PublicKey object and reconstructs the
     * original object.
     * @param JSONStr  String representation (in JSON) of a PublicKey object.
     * @returns The object which the input string represents.
     */
    public static deserialize(JSONStr: string): PublicKey {
        const toDeserialize = JSON.parse(JSONStr);

        return new PublicKey(
            mcl.deserializeHexStrToG1(toDeserialize.g),
            toDeserialize.Ys.map(mcl.deserializeHexStrToG1),
            mcl.deserializeHexStrToG2(toDeserialize.gt),
            mcl.deserializeHexStrToG2(toDeserialize.Xt),
            toDeserialize.Yts.map(mcl.deserializeHexStrToG2)
        );
    }
}

/**
 * The secret key used for the [[Issuer]]. Property names are according to the paper.
 */
export class SecretKey implements Serializable {
    constructor(public X: mcl.G1) {}

    /**
     * Transforms a SecretKey object into its string representation.
     * @returns String representation of the SecretKey object.
     */
    public serialize(): string {
        return this.X.serializeToHexStr();
    }

    /**
     * Static method that takes a string representation of a SecretKey object and reconstructs the
     * original object.
     * @param hexStr  String representation (in hex) of a SecretKey object.
     * @returns The object which the input string represents.
     */
    public static deserialize(hexStr: string): SecretKey {
        return new SecretKey(mcl.deserializeHexStrToG1(hexStr));
    }
}

/**
 * The key pair (public key, secret key) that the [[Issuer]] creates.
 */
export class KeyPair implements Serializable {
    public publicKey: PublicKey;
    public secretKey: SecretKey;

    /**
     * Creates a key pair.
     * @param r  The total number of attributes the credential carries.
     */
    public constructor(public r: number) {
        const g: mcl.G1 = mcl.hashAndMapToG1("g");
        const gt: mcl.G2 = mcl.hashAndMapToG2("gtilde");

        const x: mcl.Fr = randomFr();
        const ys: mcl.Fr[] = Array(r)
            .fill(1)
            .map(randomFr);

        this.publicKey = new PublicKey(
            g,
            ys.map(y => mcl.mul(g, y)),
            gt,
            mcl.mul(gt, x),
            ys.map(y => mcl.mul(gt, y))
        );
        this.secretKey = new SecretKey(mcl.mul(g, x));
    }

    /**
     * Transforms a KeyPair object into its string representation.
     * @returns String representation of the object.
     */
    public serialize(): string {
        return JSON.stringify({
            r: this.r,
            publicKey: this.publicKey.serialize(),
            secretKey: this.secretKey.serialize()
        });
    }

    /**
     * Saves the serialized KeyPair object in a file.
     * @param filepath  The location of the file where the object will be stored.
     */
    public saveToFile(filepath: string): void {
        const fs = require("fs"); // TODO: exclude fs from browserify bundle
        fs.writeFileSync(filepath, this.serialize());
    }

    /**
     * Static method that takes a string representation of a KeyPair object and reconstructs the
     * original object.
     * @param JSONStr  String representation (in JSON) of a KeyPair object.
     * @returns The object which the input string represents.
     */
    public static deserialize(JSONStr: string): KeyPair {
        const toDeserialize = JSON.parse(JSONStr);
        const keyPair: KeyPair = new KeyPair(toDeserialize.r);
        keyPair.publicKey = PublicKey.deserialize(toDeserialize.publicKey);
        keyPair.secretKey = SecretKey.deserialize(toDeserialize.secretKey);
        return keyPair;
    }

    /**
     * Static method that loads a KeyPair object from a file.
     * @param r  The total number of attributes the credential carries.
     * @param filepath  The path to the file where the KeyPair object is stored.
     * @returns The object which is stored in the file.
     */
    public static loadFromFile(r: number, filepath: string): KeyPair {
        const fs = require("fs");
        let keyPair: KeyPair;

        if (fs.existsSync(filepath)) {
            keyPair = KeyPair.deserialize(fs.readFileSync(filepath));
            if (keyPair.r !== r) {
                throw new Error(
                    "KeyPair: could not load key pair because given r parameter does not match the file's"
                );
            }
        } else {
            keyPair = new KeyPair(r);
            keyPair.saveToFile(filepath);
        }

        return keyPair;
    }
}

/**
 * A non-interactive proof of knowledge of the type PK{ (x, y_1, ..., y_r): C = g^x * PROD(g_i^{y_i}) }.
 * It is of the form (challenge, s, s_1, ..., s_r).
 */
export class ProofOfKnowledge implements Serializable {
    public constructor(
        public challenge: mcl.Fr,
        public s: mcl.Fr,
        public sis: mcl.Fr[]
    ) {}

    /**
     * Transforms ProofOfKnowledge object into its string representation.
     * @returns String representation of the ProofOfKnowledge object.
     */
    public serialize(): string {
        return JSON.stringify({
            challenge: this.challenge.serializeToHexStr(),
            s: this.s.serializeToHexStr(),
            sis: this.sis.map(si => si.serializeToHexStr())
        });
    }

    /**
     * Static method that takes a string representation of a ProofOfKnowledge object and reconstructs the
     * original object.
     * @param JSONStr  String representation (in JSON) of a ProofOfKnowledge object.
     * @returns The object which the input string represents.
     */
    public static deserialize(JSONStr: string): ProofOfKnowledge {
        const toDeserialize = JSON.parse(JSONStr);

        return new ProofOfKnowledge(
            mcl.deserializeHexStrToFr(toDeserialize.challenge),
            mcl.deserializeHexStrToFr(toDeserialize.s),
            toDeserialize.sis.map(mcl.deserializeHexStrToFr)
        );
    }
}

/**
 * The commitment on the attributes.
 * It includes the proof that the commitment is well formed.
 */
export class Commitment implements Serializable {
    public constructor(public C: mcl.G1, public proof: ProofOfKnowledge) {}

    /**
     * Transforms a Commitment object into its string representation.
     * @returns String representation of the object.
     */
    public serialize(): string {
        return JSON.stringify({
            C: this.C.serializeToHexStr(),
            proof: this.proof.serialize()
        });
    }

    /**
     * Static method that takes a string representation of a Commitment object and reconstructs the
     * original object.
     * @param JSONStr  String representation (in JSON) of a Commitment object.
     * @returns The object which the input string represents.
     */
    public static deserialize(JSONStr: string): Commitment {
        const toDeserialize = JSON.parse(JSONStr);

        return new Commitment(
            mcl.deserializeHexStrToG1(toDeserialize.C),
            ProofOfKnowledge.deserialize(toDeserialize.proof)
        );
    }
}

/**
 * The proof of knowledge of a signature.
 * See [Short Randomizable Signatures](https://eprint.iacr.org/2015/525.pdf), section 6.2.
 * Used to show a credential. Hides the hidden attributes but proves they were signed by the issuer.
 */
export class SignatureProof implements Serializable {
    public constructor(
        public proof: ProofOfKnowledge,
        public sigmaPrime: Signature
    ) {}

    /**
     * Transforms a SignatureProof object into its string representation.
     * @returns String representation of the object.
     */
    public serialize(): string {
        return JSON.stringify({
            proof: this.proof.serialize(),
            sigmaPrime: this.sigmaPrime.serialize()
        });
    }

    /**
     * Static method that takes a string representation of a SignatureProof object and reconstructs the
     * original object.
     * @param JSONStr  String representation (in JSON) of a SignatureProof object.
     * @returns The object which the input string represents.
     */
    public static deserialize(JSONStr: string): SignatureProof {
        const toDeserialize = JSON.parse(JSONStr);

        return new SignatureProof(
            ProofOfKnowledge.deserialize(toDeserialize.proof),
            Signature.deserialize(toDeserialize.sigmaPrime)
        );
    }
}

/**
 * A domain-specific pseudomyn. It is of the form nym = H(domain)^x,
 * where *x* is a secret key.
 */
export class Pseudonym implements Serializable {
    public constructor(public domain: string, public nym: mcl.G1) {}

    public serialize(): string {
        return JSON.stringify({
            domain: this.domain,
            nym: this.nym.serializeToHexStr()
        });
    }

    public static deserialize(JSONStr: string): Pseudonym {
        const toDeserialize = JSON.parse(JSONStr);

        return new Pseudonym(
            toDeserialize.domain,
            mcl.deserializeHexStrToG1(toDeserialize.nym)
        );
    }
}
