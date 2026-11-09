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
        // Fix V1 (A01:2025 Broken Access Control / IDOR): el recurso solo se entrega
        // si el id de la URL coincide con el de la sesion del servidor (String() en
        // ambos lados: la sesion guarda un numero y la URL llega como string).
        // Si no coincide, 403 y se registra el intento.
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
                // V2 (A05:2025): threshold invalido es un error del cliente -> 400,
                // no 500. Mensaje fijo, sin reflejar la entrada (evita XSS).
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
