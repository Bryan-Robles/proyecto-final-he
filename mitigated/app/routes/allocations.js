const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const {
    environmentalScripts
} = require("../../config/config");

function AllocationsHandler(db) {
    "use strict";

    const allocationsDAO = new AllocationsDAO(db);

    this.displayAllocations = (req, res, next) => {
        /*
        // Fix for A4 Insecure DOR -  take user id from session instead of from URL param
        const { userId } = req.session;
        */
        // Fix V1 (A01:2025 Broken Access Control / IDOR): el userId sale de la sesion
        // del servidor, no del parametro de la URL controlado por el cliente.
        const { userId } = req.session;
        const {
            threshold
        } = req.query;

        allocationsDAO.getByUserIdAndThreshold(userId, threshold, (err, allocations) => {
            if (err) return next(err);
            return res.render("allocations", {
                userId,
                allocations,
                environmentalScripts
            });
        });
    };
}

module.exports = AllocationsHandler;
