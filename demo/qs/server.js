"use strict";

const path = require("path");
const express = require("express");
const exphbs = require("express-handlebars");
const bodyParser = require("body-parser");
const cors = require("cors");

const qs = require("./qs");
const db = require("./db");

const app = express();

const hostname = "127.0.0.1";
const port = 3002;

const publicKeyPath = "http://127.0.0.1:3001/publicKey";

// [
//     { ip: _, nym: _, ans1: _, ans2: _ },
//     { ip: _, nym: _, ans1: _, ans2: _ },
//     ...
// ]
var answers = [];

// Handlebars ------------------------------------------
app.engine(
    ".hbs",
    exphbs({
        defaultLayout: "main",
        extname: ".hbs",
        layoutsDir: path.join(__dirname, "views/layouts")
    })
);
app.set("view engine", ".hbs");
app.set("views", path.join(__dirname, "views"));

// CORS ------------------------------------------------
app.use(cors());

// -----------------------------------------------------

// app.use("/", express.static(path.join(__dirname, "files")))

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.get("/", (request, response) => {
    console.log("Just received a request!");
    response.sendFile(path.join(__dirname, "index.html"));
});

app.post("/show", (request, response) => {
    response.send(qs.verify(request.body));
});

// app.use("/quests/", express.static(path.join(__dirname, "questionnaires")))
app.get("/quest/:questID", (request, response) => { 
    response.sendFile(path.join(__dirname, "quests/" + request.params.questID + ".html"));
});

app.post("/result/:questID", (request, response) => {
    db.insert(qs.newAnswerTableEntry(request.ip, request.body), "questionnaires");
    response.sendStatus(200);
});

app.get("/list/:questID", (request, response) => {
    db.getAll(request.params.questID, answers => {
        response.render("questResults", {
            answers: answers,
            name: request.params.questID
        });
    });
});

app.get("/listall", (request, response) => {
    db.getAll("questionnaires", answers => {
        response.render("alltable", qs.getListAllRenderObject(answers));
    });
});


// Linking tokens -------
app.get("/sendtokens", (request, response) => { 
    response.sendFile(path.join(__dirname, "sendtokens.html"));
});

app.post("/token/:studyID", (request, response) => {
    qs.storeToken(request.params.studyID, request.body.tokenStr);
    response.sendStatus(200);
});

app.get("/showlinks/:studyID", (request, response) => {
    db.getAll("questionnaires", answers => {
        response.render("alltable", qs.getShowLinksRenderObject(answers, request.params.studyID));
    });
});


app.get("/cleardb", (request, response) => {
    db.clear();
    response.sendStatus(200);
});

app.listen(port, err => {
    if (err) {
        return console.log("something bad happened", err);
    }

    try {
        qs.setup(publicKeyPath);
    } catch (e) {
        console.err(e);
    }

    console.log(`server is listening on http://${hostname}:${port}/`);
});
