"use strict";
import {
    Pseudonym,
    PublicKey,
    Serializable,
    Signature,
    User,
    Verifier,
    internal,
    mcl /*THIS IS A HACK - BE CAREFUL*/,
    randomFr
} from "ps-credentials";

const GENERATOR_H: string = "GENERATOR_H";

/**
 * Proof of knowledge proving correctness of the Linking Information as well as
 * proving knowledge of a credential and correctness of a domain specific
 * pseudonym.
 */
export class LinkInfoCorrectness implements Serializable {
    public constructor(
        public challenge: mcl.Fr,
        public exponents: mcl.Fr[],
        public signature: Signature
    ) {}

    /**
     * Transforms a LinkInfoCorrectness object into its string representation.
     * @returns String representation of the LinkInfoCorrectness object.
     */
    public serialize(): string {
        return JSON.stringify({
            challenge: this.challenge.serializeToHexStr(),
            exponents: this.exponents.map(exp => exp.serializeToHexStr()),
            signature: this.signature.serialize()
        });
    }

    /**
     * Static method that takes a string representation of a LinkInfoCorrectness
     * object and reconstructs the original object.
     * @param JSONStr  String representation (in JSON) of a LinkInfoCorrectness object.
     * @returns The object which the input string represents.
     */
    public static deserialize(JSONStr: string): LinkInfoCorrectness {
        const toDeserialize = JSON.parse(JSONStr);

        return new LinkInfoCorrectness(
            mcl.deserializeHexStrToFr(toDeserialize.challenge),
            toDeserialize.exponents.map(mcl.deserializeHexStrToFr),
            Signature.deserialize(toDeserialize.signature)
        );
    }
}

/**
 * Linking information pair (s,t) that enables linking of answers - but only
 * if the linker knows the linking token. They are of the form,
 *
 * **s = h^z** and **t = e(H(studyID), s)^x**,
 *
 * where ***z*** is a random field element, ***x*** is the user's secret key, and
 * ***studyID*** is the identifier of the study.
 *
 * The object also includes a proof of knowledge proving the correctness of the
 * generated elements. See [[LinkInfoCorrectness]].
 */
export class LinkInfo implements Serializable {
    public constructor(
        public s: mcl.G2,
        public t: mcl.GT,
        public proof: LinkInfoCorrectness
    ) {}

    /**
     * Transforms a LinkInfo object into its string representation.
     * @returns String representation of the LinkInfo object.
     */
    public serialize(): string {
        return JSON.stringify({
            s: this.s.serializeToHexStr(),
            t: this.t.serializeToHexStr(),
            proof: this.proof.serialize()
        });
    }

    /**
     * Static method that takes a string representation of a LinkInfo
     * object and reconstructs the original object.
     * @param JSONStr  String representation (in JSON) of a LinkInfo object.
     * @returns The object which the input string represents.
     */
    public static deserialize(JSONStr: string): LinkInfo {
        const toDeserialize = JSON.parse(JSONStr);

        return new LinkInfo(
            mcl.deserializeHexStrToG2(toDeserialize.s),
            mcl.deserializeHexStrToGT(toDeserialize.t),
            LinkInfoCorrectness.deserialize(toDeserialize.proof)
        );
    }
}

export class Answer implements Serializable {
    public constructor(
        public questionnaireID: string,
        public answer: { [question: string]: string }, // TODO: think about about representation of answer
        public linkInfos: { [studyID: string]: LinkInfo }
    ) {}

    /**
     * Transforms an Answer object into its string representation.
     * @returns String representation of the Answer object.
     */
    public serialize(): string {
        const serializedLinkInfo: { [studyID: string]: string } = {};
        Object.entries(this.linkInfos).forEach(([studyID, info]) => {
            serializedLinkInfo[studyID] = info.serialize();
        });

        return JSON.stringify({
            questionnaireID: this.questionnaireID,
            answer: this.answer,
            linkInfos: serializedLinkInfo
        });
    }

    /**
     * Static method that takes a string representation of an Answer
     * object and reconstructs the original object.
     * @param JSONStr  String representation (in JSON) of an Answer object.
     * @returns The object which the input string represents.
     */
    public static deserialize(JSONStr: string): Answer {
        const toDeserialize = JSON.parse(JSONStr);
        const linkInfos: { [studyID: string]: LinkInfo } = {};

        Object.entries(toDeserialize.linkInfos).forEach(
            ([studyID, info]: [string, string]) => {
                linkInfos[studyID] = LinkInfo.deserialize(info);
            }
        );

        return new Answer(
            toDeserialize.questionnaireID,
            toDeserialize.answer,
            linkInfos
        );
    }
}

/**
 * The entity that answers questionnaires.
 */
export class Student {
    private key: mcl.Fr;
    public credUser: User;

    public constructor(
        private issuerPublicKey: PublicKey,
        private attributes: string[],
        private sig: Signature,
        private hiddenSetIdxs: number[],
        private keyIdx: number = 0
    ) {
        this.key = mcl.hashToFr(attributes[keyIdx]);
        this.credUser = new User();
    }

    // s = h^z, so the commitment is W = h^w
    private getSRandomizerCommitment(randomizer: mcl.Fr): mcl.G2 {
        const h: mcl.G2 = mcl.hashAndMapToG2(GENERATOR_H);
        return mcl.mul(h, randomizer);
    }

    // t = e(H(studyID), s)^x, so the commitment is W = e(H(studyID), s)^w
    private getTRandomizerCommitment(
        studyID: string,
        s: mcl.G2,
        randomizer: mcl.Fr
    ): mcl.GT {
        // W = e(H(studyID), s)^w which is equal to
        // W = e(H(studyID), s*w)
        return mcl.pairing(mcl.hashAndMapToG1(studyID), mcl.mul(s, randomizer));
    }

    private proveCorrectnessOfAnswer(
        sig: Signature,
        v: mcl.Fr,
        studyID: string,
        nym: Pseudonym,
        z: mcl.Fr,
        s: mcl.G2,
        t: mcl.GT
    ): LinkInfoCorrectness {
        // We need one randomizer per secret
        // The secrets here are: *v* from the signature, the hidden
        // attributes (which includes the secret key), and *z* from the LinkInfo
        const randomizers = {
            cred: internal.generateRandomizers(this.hiddenSetIdxs.length + 1),
            z: randomFr()
        };

        const W1: mcl.GT = internal.getCredentialRandomizersCommitment(
            sig,
            this.issuerPublicKey,
            randomizers.cred,
            this.hiddenSetIdxs
        );
        const W2: mcl.G1 = internal.getNymRandomizerCommitment(
            nym.domain,
            // TODO: this can be improved -> use idea of creating object for randomizers
            randomizers.cred[this.hiddenSetIdxs.indexOf(this.keyIdx) + 1]
        );
        const W3: mcl.G2 = this.getSRandomizerCommitment(randomizers.z);
        const W4: mcl.GT = this.getTRandomizerCommitment(
            studyID,
            s,
            randomizers.cred[this.hiddenSetIdxs.indexOf(this.keyIdx) + 1]
        );

        // TODO: Should include the answer information in the challenge
        // for the proof to work as a signature
        const c: mcl.Fr = internal.createChallenge(
            this.issuerPublicKey.gt,
            this.issuerPublicKey.Xt,
            sig.sigma1,
            sig.sigma2,
            ...this.issuerPublicKey.Yts, // TODO: only add used Ys
            W1,
            nym.nym,
            mcl.hashAndMapToG1(nym.domain),
            W2,
            s,
            mcl.hashAndMapToG2(GENERATOR_H),
            W3,
            t,
            mcl.hashAndMapToG1(studyID),
            W4
        );

        const hashedAttrs: mcl.Fr[] = this.hiddenSetIdxs.map(hiddenIdx =>
            mcl.hashToFr(this.attributes[hiddenIdx])
        );

        const exponents: mcl.Fr[] = internal.getProofExponents(
            c,
            randomizers.cred.concat(randomizers.z),
            [v].concat(hashedAttrs).concat(z)
        );

        return new LinkInfoCorrectness(c, exponents, sig);
    }

    /**
     * Creates a new linking information pair (s,t) and it's proof of
     * correctness - see [[LinkInfo]].
     * @param questionnaireID  The identifier for the questionnaire.
     * @param studyID  The identifier for the study.
     * @param key  The user's secret key.
     * @returns The linking information pair.
     */
    private newLinkInfo(questionnaireID: string, studyID: string): LinkInfo {
        const z: mcl.Fr = randomFr();
        const h: mcl.G2 = mcl.hashAndMapToG2(GENERATOR_H);
        // s = h*z
        const s = mcl.mul(h, z);
        // t = e(H(studyID), s)^key
        // which is equal to t = e(H(studyID), s*key)
        const t = mcl.pairing(
            mcl.hashAndMapToG1(studyID),
            mcl.mul(s, this.key)
        );

        const [sigmaPrime, v]: [
            Signature,
            mcl.Fr
        ] = internal.randomizeSignature(this.sig);

        const nym: Pseudonym = this.credUser.createDomainSpecificNym(
            questionnaireID,
            this.attributes[this.keyIdx]
        );

        const proof: LinkInfoCorrectness = this.proveCorrectnessOfAnswer(
            sigmaPrime,
            v,
            studyID,
            nym,
            z,
            s,
            t
        );

        return new LinkInfo(s, t, proof);
    }

    /**
     * Returns an answer including the information necessary to link it
     * in the future.
     * @param questionnaireID  The identifier of the questionnaire.
     * @param studyIDs  The identifiers for the several studies that wish
     * to link this answer.
     * @param answerObj  The object containing the answers to the several
     * questions of the questionnaire.
     * @param key  The user's secret key.
     * @returns The linking information pair (s,t).
     */
    public tagAnswer(
        questionnaireID: string,
        studyIDs: string[],
        answerObj: { [question: string]: string }
    ): Answer {
        const linkInfos: { [studyID: string]: LinkInfo } = {};

        studyIDs.forEach(studyID => {
            linkInfos[studyID] = this.newLinkInfo(questionnaireID, studyID);
        });

        return new Answer(questionnaireID, answerObj, linkInfos);
    }

    /**
     * Computes the linking token for a specific study. This is is used in
     * combination with [[LinkInfo]] to link answers made by the same
     * student, i.e. answers signed with the same key.
     * @param studyID  The identifier for the study.
     * @param key  The user's secret key.
     * @returns The linking token.
     */
    public getLinkToken(studyID: string): mcl.G1 {
        // H(studyID)^x
        return mcl.mul(mcl.hashAndMapToG1(studyID), this.key);
    }
}

/**
 * The entity that wants to study [[Student]]'s answers. With the
 * permission of the student, the researcher can link some of the
 * student's answers.
 */
export class Researcher extends Verifier {
    /**
     * Contains the already linked answers. The answers are grouped by
     * the [[Student]]'s linking token. This way the linking token
     * acts as a pseudonym for the user within the study.
     */
    public links: { [linkToken: string]: Answer[] };

    /**
     * Answers to the questionnaires grouped by questionnaireID
     */
    public answers: { [questionnaireID: string]: Answer[] };

    /**
     * Decrypted linking tokens provided by the students.
     */
    public tokens: mcl.G1[]; // TODO create wrapper object

    public constructor(
        /**
         * The ID of the study organized by the [[Researcher]]. Used to create
         * the linking information and linking token.
         */
        public studyID: string
    ) {
        super();
        this.links = {};
        this.answers = {};
        this.tokens = [];
    }

    public checkLink(answer: Answer, tokenStr: string): boolean {
        const linkInfo = answer.linkInfos[this.studyID];
        const token: mcl.G1 = mcl.deserializeHexStrToG1(tokenStr);
        return mcl.pairing(token, linkInfo.s).isEqual(linkInfo.t);
    }

    /**
     * Fills the *links* array with the linked answers. This is
     * obtained by combining the linking information ([[LinkInfo]]) and
     * the linking token.
     */
    public linkAnswers() {
        for (const quest of Object.values(this.answers)) {
            for (const ans of quest) {
                // linkInfo wraps the values s and t
                const linkInfo = ans.linkInfos[this.studyID];

                // token is the linking token T
                for (const token of this.tokens) {
                    // e(T, s) = t
                    if (mcl.pairing(token, linkInfo.s).isEqual(linkInfo.t)) {
                        // TODO: should check correctness of linkinfo before this
                        if (this.links[token.serializeToHexStr()]) {
                            this.links[token.serializeToHexStr()].push(ans);
                        } else {
                            this.links[token.serializeToHexStr()] = [ans];
                        }
                    }
                }
            }
        }
    }

    // W' = h*response - s*c
    // where response = w + cz and s = h*z
    private getSCandidateW(
        s: mcl.G2,
        response: mcl.Fr,
        challenge: mcl.Fr
    ): mcl.G2 {
        const h: mcl.G2 = mcl.hashAndMapToG2(GENERATOR_H);
        return mcl.sub(mcl.mul(h, response), mcl.mul(s, challenge));
    }

    // W' = e(H(studyID), s)^response / t^c
    // where reponse = w + cx and t = e(H(studyID), s)^x
    private getTCandidateW(
        t: mcl.GT,
        s: mcl.G2,
        studyID: string,
        response: mcl.Fr,
        challenge: mcl.Fr
    ): mcl.GT {
        return mcl.div(
            mcl.pow(mcl.pairing(mcl.hashAndMapToG1(studyID), s), response),
            mcl.pow(t, challenge)
        );
    }

    private checkLinkCorrectness(
        linkInfo: LinkInfo,
        cred: Signature,
        publicKey: PublicKey,
        keyIdx: number,
        hiddenSetIdxs: number[],
        disclosureSetIdxs: number[],
        hashedDisclosedAttributes: mcl.Fr[],
        nym: Pseudonym
    ): boolean {
        const proof: LinkInfoCorrectness = linkInfo.proof;

        const W1prime: mcl.GT = internal.getCredentialCandidateW(
            cred,
            linkInfo.proof.exponents.slice(0, hiddenSetIdxs.length + 1),
            linkInfo.proof.challenge,
            publicKey,
            hiddenSetIdxs,
            disclosureSetIdxs,
            hashedDisclosedAttributes
        );

        const W2prime: mcl.G1 = internal.getNymCandidateW(
            nym,
            linkInfo.proof.exponents[1],
            linkInfo.proof.challenge
        );

        const W3prime: mcl.G2 = this.getSCandidateW(
            linkInfo.s,
            // The last position of the array contains the response that corresponds
            // to the the secret *z*
            linkInfo.proof.exponents[linkInfo.proof.exponents.length - 1],
            linkInfo.proof.challenge
        );

        const W4prime: mcl.GT = this.getTCandidateW(
            linkInfo.t,
            linkInfo.s,
            this.studyID,
            linkInfo.proof.exponents[keyIdx + 1],
            linkInfo.proof.challenge
        );

        const cPrime: mcl.Fr = internal.createChallenge(
            publicKey.gt,
            publicKey.Xt,
            cred.sigma1,
            cred.sigma2,
            ...publicKey.Yts, // TODO: only add used Ys
            W1prime,
            nym.nym,
            mcl.hashAndMapToG1(nym.domain),
            W2prime,
            linkInfo.s,
            mcl.hashAndMapToG2(GENERATOR_H),
            W3prime,
            linkInfo.t,
            mcl.hashAndMapToG1(this.studyID),
            W4prime
        );

        return linkInfo.proof.challenge.isEqual(cPrime);
    }

    public checkAnswerCorrectness(
        answer: Answer,
        issuerPK: PublicKey,
        nym: Pseudonym
    ): boolean {
        const info: LinkInfo = answer.linkInfos[this.studyID];

        const keyIdx: number = 0;

        const hiddenSetIdxs: number[] = [0];
        const disclosureSetIdxs: number[] = [];
        const hashedDisclosedAttributes: mcl.Fr[] = [];

        return this.checkLinkCorrectness(
            info,
            info.proof.signature,
            issuerPK,
            keyIdx,
            hiddenSetIdxs,
            disclosureSetIdxs,
            hashedDisclosedAttributes,
            nym
        );
    }
}

export { setup, mcl } from "ps-credentials";
