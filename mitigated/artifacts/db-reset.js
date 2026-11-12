#!/usr/bin/env nodejs

"use strict";

// This script initializes the database. You can set the environment variable
// before running it (default: development). ie:
// NODE_ENV=production node artifacts/db-reset.js

const { MongoClient } = require("mongodb");
const { db } = require("../config/config");
// V3 (A04:2025): el seed tambien se guarda con bcrypt, igual que addUser().
const bcrypt = require("bcryptjs");
const SALT_ROUNDS = Math.max(10, parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12);

const USERS_TO_INSERT = [
    {
        "_id": 1,
        "userName": "admin",
        "firstName": "Node Goat",
        "lastName": "Admin",
        "password": "Admin_123",
        "isAdmin": true
    }, {
        "_id": 2,
        "userName": "user1",
        "firstName": "John",
        "lastName": "Doe",
        "benefitStartDate": "2030-01-10",
        "password": "User1_123"
    }, {
        "_id": 3,
        "userName": "user2",
        "firstName": "Will",
        "lastName": "Smith",
        "benefitStartDate": "2025-11-30",
        "password": "User2_123"
    }];

const tryDropCollection = (db, name) => {
    return new Promise((resolve, reject) => {
        db.dropCollection(name, (err, data) => {
            if (!err) {
                console.log(`Dropped collection: ${name}`);
            }
            resolve(undefined);
        });
    });
};

const parseResponse = (err, res, comm) => {
    if (err) {
        console.log("ERROR:");
        console.log(comm);
        console.log(JSON.stringify(err));
        process.exit(1);
    }
    console.log(comm);
    console.log(JSON.stringify(res));
};


// Starting here
MongoClient.connect(db, (err, db) =>  {
    if (err) {
        console.log("ERROR: connect");
        console.log(JSON.stringify(err));
        process.exit(1);
    }
    console.log("Connected to the database");

    const collectionNames = [
        "users",
        "allocations",
        "contributions",
        "memos",
        "counters"
    ];

    // remove existing data (if any), we don't want to look for errors here
    console.log("Dropping existing collections");
    const dropPromises = collectionNames.map((name) => tryDropCollection(db, name));

    // Wait for all drops to finish (or fail) before continuing
    Promise.all(dropPromises).then(() => {
        const usersCol = db.collection("users");
        const allocationsCol = db.collection("allocations");
        const countersCol = db.collection("counters");

        // reset unique id counter
        countersCol.insert({
            _id: "userId",
            seq: 3
        }, (err, data) => {
            parseResponse(err, data, "countersCol.insert");
        });

        // insert admin and test users
        // V3 - mitigado aqui: el seed se inserta con hash bcrypt.
        const usersToInsert = USERS_TO_INSERT.map((user) => Object.assign({}, user, {
            password: bcrypt.hashSync(user.password, SALT_ROUNDS)
        }));
        // V3 - mitigado aqui: credenciales fuera del log.
        const redact = (user) => Object.assign({}, user, { password: "[REDACTED]" });
        console.log("Users to insert:");
        usersToInsert.forEach((user) => console.log(JSON.stringify(redact(user))));

        usersCol.insertMany(usersToInsert, (err, data) => {
            const finalAllocations = [];

            // We can't continue if error here
            if (err) {
                console.log("ERROR: insertMany");
                console.log(JSON.stringify(err));
                process.exit(1);
            }
            // V3 - mitigado aqui: solo se registra el conteo.
            parseResponse(err, { insertedCount: data.insertedCount }, "users.insertMany");

            data.ops.forEach((user) => {
                const stocks = Math.floor((Math.random() * 40) + 1);
                const funds = Math.floor((Math.random() * 40) + 1);

                finalAllocations.push({
                    userId: user._id,
                    stocks: stocks,
                    funds: funds,
                    bonds: 100 - (stocks + funds)
                });
            });

            console.log("Allocations to insert:");
            finalAllocations.forEach(allocation => console.log(JSON.stringify(allocation)));

            allocationsCol.insertMany(finalAllocations, (err, data) => {
                parseResponse(err, data, "allocations.insertMany");
                console.log("Database reset performed successfully");
                process.exit(0);
            });

        });
    });
});
