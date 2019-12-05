/// <reference path="../mcl.d.ts"/>

"use strict";
import { Answer, LinkInfo, Researcher, Student, setup } from "../linking";
// import * as ps from "ps-credentials"; // WHY DOESN'T THIS WORK?
import * as ps from "../../node_modules/ps-credentials/src/index";
import { expect } from "chai";
import "mocha";

function getPSsig(issuer: ps.Issuer, key: string): ps.Signature {
    const user: ps.User = new ps.User();
    const commitment: ps.Commitment = user.createCommitment(issuer.publicKey, [
        key
    ]);
    const blindSig: ps.Signature = issuer.blindSign(commitment, []);
    return user.unblindSignature(blindSig);
}

function compareAnswers(ans1: Answer, ans2: Answer) {
    if (
        ans1.questionnaireID !== ans2.questionnaireID &&
        JSON.stringify(ans1.answer) !== JSON.stringify(ans2.answer) &&
        Object.keys(ans1.linkInfos).length !==
            Object.keys(ans2.linkInfos).length
    )
        return false;

    for (const studyID of Object.keys(ans1.linkInfos)) {
        if (
            !Object.keys(ans2.linkInfos).includes(studyID) ||
            ans1.linkInfos[studyID].serialize() !==
                ans2.linkInfos[studyID].serialize()
        )
            return false;
    }

    return true;
}

function checkStudentLinking(answers: Answer[]) {
    let studentID: string = answers[0].answer["a"];

    for (const ans of answers) {
        if (ans.answer["a"] !== studentID) return false;
    }

    return true;
}

/**
 * For these test every questionnaire has a single question we call "a".
 * We also force the same student to always answer with her ID in every
 * questionnaire. This way we can check if linking is being done correctly.
 */
function checkLinking(
    links: { [linkToken: string]: Answer[] },
    studentNumber: number
) {
    if (Object.values(links).length !== studentNumber) return false;

    for (const answers of Object.values(links)) {
        if (!checkStudentLinking(answers)) return false;
    }

    return true;
}

function printLinks(researcher: Researcher) {
    Object.entries(researcher.links).forEach(([nym, answers]) => {
        console.log(
            nym + ": " + answers.map(ans => JSON.stringify(ans.answer))
        );
    });
}

describe("Unit test for proving and checking correctness of ZKPs on linking info", () => {
    let questIDs: string[];

    let studyID1: string;
    let studyID2: string;
    let studyID3: string;
    let studyIDs: string[];

    let issuer: ps.Issuer;

    let key1: string;
    let sig1: ps.Signature;
    let student1: Student;
    let answers1: Answer[];

    let key2: string;
    let sig2: ps.Signature;
    let student2: Student;
    let answers2: Answer[];

    let key3: string;
    let sig3: ps.Signature;
    let student3: Student;
    let answers3: Answer[];

    before(async () => {
        await setup();

        issuer = new ps.Issuer(1);

        questIDs = ["id1", "id2", "id3"];

        studyID1 = "studyID1";
        studyID2 = "studyID2";
        studyID3 = "studyID3";
        studyIDs = [studyID1, studyID2, studyID3];

        key1 = "key1";
        sig1 = getPSsig(issuer, key1);
        student1 = new Student(issuer.publicKey, [key1], sig1, [0]);
        key2 = "key2";
        sig2 = getPSsig(issuer, key2);
        student2 = new Student(issuer.publicKey, [key2], sig2, [0]);
        key3 = "key3";
        sig3 = getPSsig(issuer, key3);
        student3 = new Student(issuer.publicKey, [key3], sig3, [0]);
    });

    it("should accept a correctly formed linkInfo", () => {
        const researcher: Researcher = new Researcher(studyID1);
        const answer: Answer = student3.tagAnswer(questIDs[0], [studyID1], {
            a: "st3"
        });

        const nym: ps.Pseudonym = student3.credUser.createDomainSpecificNym(
            questIDs[0],
            key3
        );

        expect(
            researcher.checkAnswerCorrectness(answer, issuer.publicKey, nym)
        ).to.equal(true);
    });
});
