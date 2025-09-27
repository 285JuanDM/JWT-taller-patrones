const express = require("express");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// Cargar llaves
const PRIVATE_KEY = fs.readFileSync("private.key", "utf8");
const PUBLIC_KEY = fs.readFileSync("public.key", "utf8");

// Usuarios de ejemplo (harcodeados para la demo)
const users = {
  basic: { password: "1234", role: "basic" },
  admin: { password: "admin", role: "admin" }
};

// Login - genera JWT
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!users[username] || users[username].password !== password) {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }

  const payload = {
    role: users[username].role
  };

  // Expira en 2 minutos
  const token = jwt.sign(payload, PRIVATE_KEY, {
    algorithm: "RS256",
    expiresIn: "2m"
  });

  res.json({ token });
});

// Middleware para validar JWT
function authenticateJWT(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) return res.status(403).json({ error: "Token requerido" });

  const token = authHeader.split(" ")[1];

  jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] }, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido o expirado" });

    req.user = decoded;
    next();
  });
}

// Middleware para validar roles
function authorizeRole(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "No autorizado" });
    }
    next();
  };
}

// Rutas protegidas
app.get("/saludo", authenticateJWT, authorizeRole(["basic", "admin"]), (req, res) => {
  res.send("Hola 👋");
});

app.get("/despido", authenticateJWT, authorizeRole(["admin"]), (req, res) => {
  res.send("Adiós 👋");
});

app.listen(3000, () => {
  console.log("Servidor corriendo en http://localhost:3000");
});
