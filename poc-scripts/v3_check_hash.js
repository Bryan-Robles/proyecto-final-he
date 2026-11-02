// V3 - Cryptographic Failures (OWASP A04:2025). Dueno: JuanDa.
// Uso: SOLO contra la base de datos LOCAL del laboratorio. Solo lectura.
//
// Inspecciona como se almacena el campo `password` en la coleccion `users`
// y clasifica cada valor: texto plano, hash rapido (MD5/SHA) o bcrypt
// (prefijos $2a$, $2b$ o $2y$). Nunca imprime el valor completo: lo enmascara.
//
// Ejecucion (desde la raiz del repo, Git Bash). Corre dentro del contenedor
// `web`, que ya tiene el driver `mongodb` y la variable MONGODB_URI:
//   docker compose -f vulnerable/docker-compose.yml exec -T web node - < poc-scripts/v3_check_hash.js
//   docker compose -f mitigated/docker-compose.yml  exec -T web node - < poc-scripts/v3_check_hash.js
//
// Codigo de salida: 0 = todos bcrypt (mitigado), 1 = hay inseguros, 2 = error.

"use strict";

const { MongoClient } = require("mongodb"); // driver 2.x del proyecto

const uri = process.env.MONGODB_URI || "mongodb://localhost:27017/nodegoat";
const BCRYPT_RE = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/;
const FAST_HASH = { 32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512" };

function classify(value) {
    if (typeof value !== "string" || value.length === 0) {
        return { type: "VACIO/NO-STRING", safe: false };
    }
    const m = value.match(BCRYPT_RE);
    if (m) {
        return { type: `BCRYPT (cost=${parseInt(m[1], 10)})`, safe: true };
    }
    if (/^[a-f0-9]+$/i.test(value) && FAST_HASH[value.length]) {
        return { type: `HASH RAPIDO ${FAST_HASH[value.length]} sin sal`, safe: false };
    }
    return { type: "TEXTO PLANO", safe: false };
}

function mask(value, safe) {
    if (typeof value !== "string") return String(value);
    if (safe) return `${value.slice(0, 7)}${"*".repeat(8)} (len=${value.length})`;
    return `${value.charAt(0)}${"*".repeat(8)} (len=${value.length})`;
}

MongoClient.connect(uri, (err, db) => {
    if (err) {
        console.error("[V3] ERROR conectando a Mongo:", err.message);
        process.exit(2);
    }
    console.log(`[V3] Fecha: ${new Date().toISOString()}`);
    console.log(`[V3] Destino: ${uri.replace(/\/\/[^@]*@/, "//***@")}`);
    console.log("[V3] Coleccion: users | campo: password\n");

    db.collection("users")
        .find({}, { userName: 1, password: 1 })
        .sort({ _id: 1 })
        .toArray((err, users) => {
            if (err) {
                console.error("[V3] ERROR leyendo users:", err.message);
                db.close();
                process.exit(2);
            }
            let insecure = 0;
            users.forEach((u) => {
                const c = classify(u.password);
                if (!c.safe) insecure++;
                console.log(
                    `  _id=${String(u._id).padEnd(3)} user=${String(u.userName).padEnd(12)} ` +
                    `${c.type.padEnd(28)} ${mask(u.password, c.safe)}`
                );
            });
            console.log(`\n[V3] Total: ${users.length} | inseguros: ${insecure}`);
            if (users.length === 0) {
                console.log("[V3] RESULTADO: sin usuarios (revisar seed)");
                db.close();
                process.exit(2);
            }
            if (insecure > 0) {
                console.log("[V3] RESULTADO: VULNERABLE - contrasenas recuperables desde la BD (A04:2025)");
            } else {
                console.log("[V3] RESULTADO: MITIGADO - todas las contrasenas con bcrypt");
            }
            db.close();
            process.exit(insecure > 0 ? 1 : 0);
        });
});