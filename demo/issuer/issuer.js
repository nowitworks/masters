"use strict";

const pscreds = require("ps-credentials");
const fs = require("fs");

var issuer;
const issuerAttrs = [];

exports.setup = async (r = 1, keyFile = "keys.json") => {
    console.log("issuer.js: setup beginning");
    await pscreds.setup();
    issuer = new pscreds.Issuer(r, keyFile);
    console.log("issuer.js: Issuer is ready!");
};

exports.getPublicKey = () => {
    return issuer.publicKey.serialize();
}

exports.issue = commitmentJSON => {
    console.log("issuer.js: received commitment");
    const commitment = pscreds.Commitment.deserialize(commitmentJSON);
    console.log(
        "issuer.js: successfully deserialized commitment. Issuing credential..."
    );
    const issuerDetAttributes = [];//issuerAttrs.slice(0, issuer.r - commitment.proof.sis.length) // TODO: find alternative
    const cred = issuer.blindSign(
        commitment,
        issuerDetAttributes
    );
    console.log("issuer.js: commitment signed");

    return {
        cred: cred.serialize(),
        attrs: issuerDetAttributes
    }
};
