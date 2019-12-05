"use strict";

const MongoClient = require("mongodb").MongoClient;
const url = "mongodb://localhost:27017/";
const dbname = "answers";

/**
 * @param answer  answer object
 * @param table   id of the questionnaire
 */
exports.insert = (answer, table) => {
    MongoClient.connect(url, { useNewUrlParser: true }, function(err, db) {
        if (err) throw err;
        const dbo = db.db(dbname);

        dbo.collection(table).insertOne(answer, function(err, res) {
            if (err) throw err;
            console.log("Number of documents inserted: " + res.insertedCount);
            db.close();
        });
    });
};

exports.getAll = (table, callback) => {
    MongoClient.connect(url, { useNewUrlParser: true }, function(err, db) {
        if (err) throw err;
        var dbo = db.db(dbname);

        dbo.collection(table)
            .find({}, { projection: { _id: 0 } }) // add here the fields to exclude
            .toArray(function(err, result) {
                if (err) throw err;

                callback(result);
                db.close();
            });
    });
};

exports.clear = () => {
    MongoClient.connect(url, { useNewUrlParser: true }, function(err, db) {
        if (err) throw err;
        const dbo = db.db(dbname);

        dbo.dropDatabase();
        db.close();
    });
};
