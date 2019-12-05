"use strict";

const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const lti = require("ims-lti");

const issuer = require("./issuer");

const app = express();

const hostname = "127.0.0.1";
const port = 3001;

const ltiKey = "issuer.consumer.key";
const ltiSecret = "issuerSecretKey";

// CORS ------------------------------------------------
// TODO: add CORS options
app.use(cors());

// -----------------------------------------------------

app.use(bodyParser.text());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// We should arrive at this page through LTI
// so the method has to be POST
app.post("/", (request, response) => {
    // Here we start by checking if the LTI access is valid
    // If LTI launch is not valid, load error page
    // If LTI launch is valid, load page to initiate issuance
    if (request.body["oauth_consumer_key"] === ltiKey) {
        var provider = new lti.Provider(ltiKey, ltiSecret);

        //Check if the Oauth is valid.
        provider.valid_request(request, function(err, isValid) {
            if (err) {
                console.log("Error in LTI Launch:" + err);
                response.status(401).sendFile(path.join(__dirname, "LTIerror.html"));
            } else {
                if (!isValid) {
                    console.log("\nError: Invalid LTI launch.");
                    response.status(401).sendFile(path.join(__dirname, "LTIerror.html"));
                } else {
                    // User is authorized so we can initiate issuance
                    // TODO: check other parameters: if user is a student, etc.
                    console.log("LTI authentication successful");
                    response.sendFile(path.join(__dirname, "index.html"));
                }
            }
        });
    } else {
        console.log("LTI key does not match...");
        response.status(401).sendFile(path.join(__dirname, "LTIerror.html"));
    }
});

// keep compatibility with LTI-less demo
app.get("/", (request, response) => {
    response.sendFile(path.join(__dirname, "index.html"));
});

app.get("/publicKey", (request, response) => {
    try {
        response.send(issuer.getPublicKey());
    } catch (err) {
        console.err(err);
    }
});

app.post("/issue", (request, response) => {
    console.log(request.body);
    try {
        response.json(issuer.issue(request.body));
    } catch (err) {
        console.err(err);
    }
});

app.listen(port, err => {
    if (err) {
        return console.log("something bad happened", err);
    }

    try {
        issuer.setup();
    } catch (error) {
        console.err(error);
    }

    console.log(`server is listening on http://${hostname}:${port}/`);
});
