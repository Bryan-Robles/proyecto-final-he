const UserDAO = require("./user-dao").UserDAO;

/* The AllocationsDAO must be constructed with a connected database object */
const AllocationsDAO = function(db){

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof AllocationsDAO)) {
        console.log("Warning: AllocationsDAO constructor called without 'new' operator");
        return new AllocationsDAO(db);
    }

    const allocationsCol = db.collection("allocations");
    const userDAO = new UserDAO(db);

    this.update = (userId, stocks, funds, bonds, callback) => {
        const parsedUserId = parseInt(userId);

        // Create allocations document
        const allocations = {
            userId: userId,
            stocks: stocks,
            funds: funds,
            bonds: bonds
        };

        allocationsCol.update({
            userId: parsedUserId
        }, allocations, {
            upsert: true
        }, err => {

            if (!err) {

                console.log("Updated allocations");

                userDAO.getUserById(userId, (err, user) => {

                    if (err) return callback(err, null);

                    // add user details
                    allocations.userId = userId;
                    allocations.userName = user.userName;
                    allocations.firstName = user.firstName;
                    allocations.lastName = user.lastName;

                    return callback(null, allocations);
                });
            }

            return callback(err, null);
        });
    };

    this.getByUserIdAndThreshold = (userId, threshold, callback) => {
        const parsedUserId = parseInt(userId);

        // V2 (A05:2025) NoSQL Injection - fix de causa raiz.
        // El codigo vulnerable interpolaba 'threshold' (entrada del usuario) dentro
        // de una clausula $where, que ejecuta JavaScript en el motor de Mongo. Aqui:
        //  1) 'threshold' debe ser un string de 1-2 digitos (0..99). La regex
        //     ^\d{1,2}$ rechaza tambien arrays (?threshold=5&threshold=6, que
        //     llega como array -> typeof !== "string"), "1e1", "0x10" y espacios,
        //     que Number() aceptaria.
        //  2) Se elimina $where y se usa el operador nativo $gt con el numero ya
        //     validado. Ninguna entrada del usuario se evalua como codigo.
        //  3) El error se devuelve por callback con un mensaje FIJO: no se incluye
        //     la entrada, para no reflejarla en la pagina de error (autoescape off
        //     => evitar XSS reflejado).
        let criteria = { userId: parsedUserId };
        if (threshold !== undefined && threshold !== "") {
            if (typeof threshold !== "string" || !/^\d{1,2}$/.test(threshold)) {
                // Se marca el error para que el handler responda 400 (error del
                // cliente) en vez de 500. El mensaje es fijo, sin la entrada.
                const invalidThresholdError = new Error("Invalid threshold");
                invalidThresholdError.invalidThreshold = true;
                return callback(invalidThresholdError, null);
            }
            criteria = {
                userId: parsedUserId,
                stocks: { $gt: Number(threshold) }
            };
        }

        allocationsCol.find(criteria).toArray((err, allocations) => {
            if (err) return callback(err, null);
            if (!allocations.length) return callback("ERROR: No allocations found for the user", null);

            let doneCounter = 0;
            const userAllocations = [];

            allocations.forEach( alloc => {
                userDAO.getUserById(alloc.userId, (err, user) => {
                    if (err) return callback(err, null);

                    alloc.userName = user.userName;
                    alloc.firstName = user.firstName;
                    alloc.lastName = user.lastName;

                    doneCounter += 1;
                    userAllocations.push(alloc);

                    if (doneCounter === allocations.length) {
                        callback(null, userAllocations);
                    }
                });
            });
        });
    };

};

module.exports.AllocationsDAO = AllocationsDAO;
