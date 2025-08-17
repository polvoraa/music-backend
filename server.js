import express from "express";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from "path";

const app = express();
app.use(express.json()); // ler JSON do front

// === Banco de Dados ===
const db = new sqlite3.Database("./users.db");

// cria tabela se não existir
db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT)");

// === Rotas ===

// Registrar usuário
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Preencha email e senha" });

  const hash = await bcrypt.hash(password, 10);

  db.run("INSERT INTO users (email, password) VALUES (?, ?)", [email, hash], function (err) {
    if (err) return res.status(400).json({ error: "Email já existe" });
    res.json({ message: "Usuário registrado com sucesso!" });
  });
});

// Login usuário
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Preencha email e senha" });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (!user) return res.status(400).json({ error: "Usuário não encontrado" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Senha inválida" });

    const token = jwt.sign({ id: user.id }, "segredo123", { expiresIn: "1h" });
    res.json({ message: "Login realizado!", token });
  });
});

// Rota protegida (precisa de token)
app.get("/profile", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, "segredo123", (err, user) => {
    if (err) return res.sendStatus(403);
    res.json({ message: "Área protegida", user });
  });
});

// === Servir frontend junto (se quiser opção 2) ===
app.use(express.static(path.resolve("./"))); // serve index.html e cia

// Rodar servidor
app.listen(3000, () => console.log("Servidor rodando em http://localhost:3000"));
