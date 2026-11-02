// V3 (A04:2025): bcryptjs (JS puro, sin compilacion nativa en node:12-alpine)
// reemplaza a bcrypt-nodejs 0.0.3, abandonado y marcado "deprecated" en npm.
const bcrypt = require("bcryptjs");

// V3: factor de costo de bcrypt (2^12 rondas de expansion de clave, ~300 ms
// por hash con bcryptjs). Configurable con BCRYPT_SALT_ROUNDS, nunca < 10.
const SALT_ROUNDS = Math.max(10, parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12);

/* The UserDAO must be constructed with a connected database object */
function UserDAO(db) {

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof UserDAO)) {
        console.log("Warning: UserDAO constructor called without 'new' operator");
        return new UserDAO(db);
    }

    const usersCol = db.collection("users");

    this.addUser = (userName, firstName, lastName, password, email, callback) => {

        // V3: hash asincrono (no bloquea el event loop). bcrypt genera una sal
        // aleatoria por usuario y la guarda dentro del hash ($2a$12$<sal><hash>).
        bcrypt.hash(password, SALT_ROUNDS, (err, passwordHash) => {
            if (err) {
                return callback(err, null);
            }

            // Create user document
            const user = {
                userName,
                firstName,
                lastName,
                benefitStartDate: this.getRandomFutureDate(),
                password: passwordHash // V3: nunca se guarda el valor recibido
                /*
                // Fix for A2-1 - Broken Auth
                // Stores password  in a safer way using one way encryption and salt hashing
                password: bcrypt.hashSync(password, bcrypt.genSaltSync())
                */
            };

            // Add email if set
            if (email) {
                user.email = email;
            }

            this.getNextSequence("userId", (err, id) => {
                if (err) {
                    return callback(err, null);
                }
                console.log(typeof(id));

                user._id = id;
                usersCol.insert(user, (err, result) => !err ? callback(null, result.ops[0]) : callback(err, null));
            });
        });
    };

    this.getRandomFutureDate = () => {
        const today = new Date();
        const day = (Math.floor(Math.random() * 10) + today.getDay()) % 29;
        const month = (Math.floor(Math.random() * 10) + today.getMonth()) % 12;
        const year = Math.ceil(Math.random() * 30) + today.getFullYear();
        return `${year}-${("0" + month).slice(-2)}-${("0" + day).slice(-2)}`;
    };

    this.validateLogin = (userName, password, callback) => {

        // Helper function to compare passwords
        // V3: firma corregida. El original declaraba (fromDB, fromUser) pero se
        // llamaba con (password, user.password): nombres invertidos.
        // bcrypt.compare(texto_plano, hash): con el orden invertido devuelve
        // false sin lanzar error. Asincrono para no bloquear el event loop.
        const comparePassword = (plainFromUser, hashFromDB, cb) => {
            if (typeof plainFromUser !== "string" || typeof hashFromDB !== "string") {
                return cb(null, false);
            }
            return bcrypt.compare(plainFromUser, hashFromDB, cb);
            /*
            // Fix for A2-Broken Auth
            // compares decrypted password stored in this.addUser()
            return bcrypt.compareSync(fromDB, fromUser);
            */
        };

        // Callback to pass to MongoDB that validates a user document
        const validateUserDoc = (err, user) => {

            if (err) return callback(err, null);

            if (user) {
                comparePassword(password, user.password, (err, isMatch) => {
                    if (err) return callback(err, null);
                    if (isMatch) {
                        callback(null, user);
                    } else {
                        const invalidPasswordError = new Error("Invalid password");
                        // Set an extra field so we can distinguish this from a db error
                        invalidPasswordError.invalidPassword = true;
                        callback(invalidPasswordError, null);
                    }
                });
            } else {
                const noSuchUserError = new Error("User: " + user + " does not exist");
                // Set an extra field so we can distinguish this from a db error
                noSuchUserError.noSuchUser = true;
                callback(noSuchUserError, null);
            }
        };

        usersCol.findOne({
            userName: userName
        }, validateUserDoc);
    };

    // This is the good one, see the next function
    this.getUserById = (userId, callback) => {
        usersCol.findOne({
            _id: parseInt(userId)
        }, callback);
    };

    this.getUserByUserName = (userName, callback) => {
        usersCol.findOne({
            userName: userName
        }, callback);
    };

    this.getNextSequence = (name, callback) => {
        db.collection("counters").findAndModify({
                _id: name
            }, [], {
                $inc: {
                    seq: 1
                }
            }, {
                new: true
            },
            (err, data) =>  err ? callback(err, null) : callback(null, data.value.seq));
    };
}

module.exports = { UserDAO };
