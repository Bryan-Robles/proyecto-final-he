const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const {
    environmentalScripts
} = require("../../config/config");

function AllocationsHandler(db) {
    "use strict";

    const allocationsDAO = new AllocationsDAO(db);

    this.displayAllocations = (req, res, next) => {
        // V1 (A01:2025) Broken Access Control / IDOR - mitigado aqui: control de propiedad
        // del recurso contra la sesion (403 + log si no coincide).
        const sessionUserId = String(req.session.userId);
        if (String(req.params.userId) !== sessionUserId) {
            console.warn(`[SEC] Posible IDOR: user ${sessionUserId} pidio ${JSON.stringify(req.params.userId)}`);
            return res.status(403).send("Forbidden");
        }
        const userId = req.session.userId;
        const {
            threshold
        } = req.query;

        allocationsDAO.getByUserIdAndThreshold(userId, threshold, (err, allocations) => {
            if (err) {
                // V2 (A05:2025) NoSQL Injection - mitigado aqui: respuesta 400 para threshold invalido.
                if (err.invalidThreshold) return res.status(400).send("Invalid threshold");
                return next(err);
            }
            return res.render("allocations", {
                userId,
                allocations,
                environmentalScripts
            });
        });
    };
}

module.exports = AllocationsHandler;
