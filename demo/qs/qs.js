"use strict";

const pscreds = require("ps-credentials");
const linking = require("linking");
const request = require("request");

var qs;
var publicKey;

var studyIDs = ["study1", "study2", "study3"];
var researchers = {};

function getPublicKey(path) {
    request(path, (error, response, body) => {
        if (!error && response.statusCode == 200) {
            publicKey = pscreds.PublicKey.deserialize(body);
            console.log("qs.js: Successfully retreived Issuer's public key");
            return;
        }
        console.log("qs.js: There was an error getting the public key...");
        throw Error(error);
    });
}

exports.setup = async publicKeyPath => {
    console.log("qs.js: setup beginning");

    await pscreds.setup();
    qs = new pscreds.Verifier();

    await linking.setup();
    // Setup the researchers
    researchers[studyIDs[0]] = new linking.Researcher(studyIDs[0]);
    researchers[studyIDs[1]] = new linking.Researcher(studyIDs[1]);
    researchers[studyIDs[2]] = new linking.Researcher(studyIDs[2]);

    getPublicKey(publicKeyPath);
    console.log("qs.js: QS (Verifier) is ready!");
};

exports.verify = response => {
    let signatureProof = pscreds.SignatureProof.deserialize(
        response.signatureProof
    );
    let showAttributes = response.showAttributes;

    return qs.checkSignatureProof(signatureProof, publicKey, showAttributes);
};

function checkNym(nymData) {
    let signatureProof = pscreds.SignatureProof.deserialize(
        nymData.signatureProof
    );
    let showAttributes = nymData.showAttributes;

    let nym = pscreds.Pseudonym.deserialize(nymData.nym);
    let keyIdx = nymData.keyIdx;

    return qs.checkSignatureProofAndNym(
        signatureProof,
        publicKey,
        showAttributes,
        nym,
        keyIdx
    );
}

function getNymStr(nymData) {
    let nym = pscreds.Pseudonym.deserialize(nymData.nym);
    return nym.nym.serializeToHexStr();
}

exports.newTableEntry = (ip, body) => {
    let nymData = JSON.parse(body.nymData);

    if (!checkNym(nymData)) {
        throw new Error("The pseudonym is invalid");
    }

    return {
        ip: Math.random() * 10000, //"127.234.54.21", //TODO get actual IP
        nym: getNymStr(nymData),
        ans1: body.optradio1,
        ans2: body.optradio2
    };
};

exports.newAnswerTableEntry = (ip, body) => {
    const nym = pscreds.Pseudonym.deserialize(body.nym);
    const answer = linking.Answer.deserialize(body.answer);

    // console.log("IP: ", ip);
    // console.log("Answer: ", Object.values(answer.answer));

    for (const studyID of Object.keys(answer.linkInfos)) {
        if (
            !researchers[studyID].checkAnswerCorrectness(answer, publicKey, nym)
        ) {
            console.log(
                "qs.js: Researcher from ",
                studyID,
                " is not ok with the answer..."
            );
        }
    }

    return {
        ip: ip, // Math.random() * 10000, //"127.234.54.21", //TODO get actual IP
        // nym: nym,
        questID: answer.questionnaireID,
        answer: body.answer,

        nymStr: nym.nym.serializeToHexStr().slice(0,16),
        ans1: answer.answer["optradio1"],
        ans2: answer.answer["optradio2"],
        linkTag: " "
    };
};

// taken from https://stackoverflow.com/questions/14446511/most-efficient-method-to-groupby-on-an-array-of-objects?page=1&tab=votes#tab-top
let groupBy = (xs, key) => {
    return xs.reduce(function(rv, x) {
        (rv[x[key]] = rv[x[key]] || []).push(x);
        return rv;
    }, {});
};

exports.getListAllRenderObject = answers => {
    const groupedAns = groupBy(answers, "questID");
    const questionnaires = Object.keys(groupedAns).map(key => {
        return { title: key, answers: groupedAns[key] };
    });
    return {
        questionnaires: questionnaires
    };
};

// Researcher ------------------------------------------------------------
exports.storeToken = (studyID, tokenStr) => {
    researchers[studyID].tokens.push(tokenStr);
};

exports.getShowLinksRenderObject = (answers, studyID) => {
    let realAnswers = [];
    for (let i = 0; i < answers.length; i++) {
        let answer = linking.Answer.deserialize(answers[i].answer);
        if (answer.linkInfos[studyID] != undefined) {
            for (const tokenStr of researchers[studyID].tokens) {
                if (researchers[studyID].checkLink(answer, tokenStr)) {
                    answers[i].linkTag = tokenStr.slice(0,16);
                }
            }
        }
    }
    return exports.getListAllRenderObject(answers);
};
