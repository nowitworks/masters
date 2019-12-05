"use strict";

// ps-credentials library accessible by global variable pscreds

let userHelper = {};
let user;
let student;

// let userAttrs = ["attr0", "attr1", "attr2", "attr3"];
let userAttrs = ["secretKey"];
// let hiddenSetIdxs = [0, 2];
let hiddenSetIdxs = [0];

userHelper.setup = async () => {
    await pscreds.setup();
    user = new pscreds.User();
};

// Issuance -----------------------------------------------------------------------
userHelper.commit = (serializedPublicKey, attributes = userAttrs) => {
    localStorage.setItem("publicKey", serializedPublicKey);
    let publicKey = pscreds.PublicKey.deserialize(serializedPublicKey);
    console.log("user.js: successfully deserialized public key");

    return user.createCommitment(publicKey, attributes).serialize();
};

userHelper.unblindAndStore = sigAndAttrs => {
    let allAttrs = userAttrs.concat(sigAndAttrs.attrs);
    localStorage.setItem("allAttrs", JSON.stringify(allAttrs));

    const blindSigJSON = sigAndAttrs.cred;
    const blindSig = pscreds.Signature.deserialize(blindSigJSON);
    console.log("user.js: successfully deserialized blind signature");

    const cred = user.unblindSignature(blindSig);
    console.log(
        "user.js: successfully unblinded signature (credential). Storing it..."
    );

    let publicKey = pscreds.PublicKey.deserialize(
        localStorage.getItem("publicKey")
    );
    // verify credential before storing
    if (pscreds.verify(publicKey, allAttrs, cred)) {
        localStorage.setItem("credential", cred.serialize());
        console.log("user.js: successfully stored credential");
        return true;
    } else {
        console.log("user.js: the received credential is not valid...");
        return false;
    }
};

// Showing ------------------------------------------------------------------------
//TODO: not need this!!!!
function getDisclosedAttributes(attributes, hiddenSetIdxs) {
    return attributes.filter((el, idx) => {
        return hiddenSetIdxs.indexOf(idx) === -1;
    });
}

function getShowFuncParameters() {
    if (!localStorage.getItem("credential")) {
        throw new Error(
            "user.js: could not find a credential stored in localStorage..."
        );
    }

    let publicKey = pscreds.PublicKey.deserialize(
        localStorage.getItem("publicKey")
    );
    let signature = pscreds.Signature.deserialize(
        localStorage.getItem("credential")
    );
    let allAttrs = JSON.parse(localStorage.getItem("allAttrs"));
    let showAttributes = allAttrs.slice();
    hiddenSetIdxs.forEach(idx => {
        showAttributes[idx] = undefined;
    });

    return {
        publicKey: publicKey,
        signature: signature,
        allAttrs: allAttrs,
        showAttributes: showAttributes
    };
}

// proveKnowledgeOfSignature(sig: Signature, publicKey: PublicKey, attributes: string[], hiddenSetIdxs: number[]): SignatureProof
userHelper.show = () => {
    let showParams;

    try {
        showParams = getShowFuncParameters();
    } catch (e) {
        console.log(e);
        return "";
    }

    return JSON.stringify({
        signatureProof: user
            .proveKnowledgeOfSignature(
                showParams.signature,
                showParams.publicKey,
                showParams.allAttrs,
                hiddenSetIdxs
            )
            .serialize(),
        showAttributes: showParams.showAttributes
    });
};

userHelper.showWithNym = (domain = "test1", keyIdx = 0) => {
    let showParams;

    try {
        showParams = getShowFuncParameters();
    } catch (e) {
        console.log(e);
        return "";
    }

    let key = showParams.allAttrs[hiddenSetIdxs[keyIdx]];
    let nym = user.createDomainSpecificNym(domain, key);

    return JSON.stringify({
        signatureProof: user
            .proveKnowledgeOfSignatureAndNym(
                showParams.signature,
                showParams.publicKey,
                showParams.allAttrs,
                hiddenSetIdxs,
                nym,
                keyIdx
            )
            .serialize(),
        showAttributes: showParams.showAttributes,
        nym: nym.serialize(),
        keyIdx: keyIdx
    });
};

// Answering questionnaires -------------------------------------------------------

function getNym(qID, keyIdx = 0) {
    let showParams;

    try {
        showParams = getShowFuncParameters();
    } catch (e) {
        console.log(e);
        return "";
    }

    const key = showParams.allAttrs[hiddenSetIdxs[keyIdx]];
    return user.createDomainSpecificNym(qID, key);
}

userHelper.setupQ = async () => {
    await userHelper.setup();
    await linking.setup();

    let showParams;
    /*publicKey: publicKey,
    signature: signature,
    allAttrs: allAttrs,
    showAttributes: showAttributes*/

    try {
        showParams = getShowFuncParameters();
    } catch (e) {
        console.log(e);
        return;
    }

    student = new linking.Student(
        showParams.publicKey,
        showParams.allAttrs,
        showParams.signature,
        [0]
    );
    console.log("user.js: Student created");
};

userHelper.answerQuest = answerData => {
    if (answerData.studyIDs === undefined) answerData.studyIDs = [];

    const answer = student.tagAnswer(
        answerData.questID,
        answerData.studyIDs,
        answerData.answerObj
    );

    return {
        answer: answer.serialize(),
        nym: getNym(answerData.questID).serialize()
    };
};

userHelper.getStrToken = studyID => {
    return student.getLinkToken(studyID).serializeToHexStr();
};
