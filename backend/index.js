import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";

const app = express();
const port = 3001;

// middleware
app.use(bodyParser.json());

// connect to DB
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "root",
  database: "bank",
  port: 3307,
});

// help function to make code look nicer
async function query(sql, params) {
  const [results] = await pool.execute(sql, params);
  return results;
}

app.get("/test", async (req, res) => {
  res.send("Test");
});

// routes/endpoints
app.post("/users", async (req, res) => {
  const { username, password } = req.body;

  // kryptera lösenordet innan det hamnar i DB

  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  console.log("hashedPassword", hashedPassword);

  try {
    const result = await query(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashedPassword]
    );

    res.status(201).send("User created");
  } catch (error) {
    console.error("Error creating user", error);
    res.status(500).send("Error creating user");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // 1. Gör select och hämta raden som matchar username

  const result = await query("SELECT * FROM users WHERE username = ?", [
    username,
  ]);

  console.log("result", result);

  const user = result[0];

  // 2. Kolla hash i DB matchar crypterat lösenord

  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(401).send("invalid usernam or password");
  }

  res.send("Login successful");
});

app.put("/new-password", async (req, res) => {
  // Hämta data från post request
  const { username, oldPassword, newPassword } = req.body;

  // Hämta raden i DB med givet username
  const result = await query("SELECT * FROM users WHERE username = ?", [
    username,
  ]);
  const user = result[0];

  // Kolla om gamla lösenordet matchar det som ligger i DB
  const passwordMatch = await bcrypt.compare(oldPassword, user.password);
  if (!passwordMatch) {
    return res.status(401).send("invalid");
  }

  // Här vet man att lösenordet matchar
  // Uppdatera databasen med nya lösenordet.
  const saltRounds = 10;
  const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
  try {
    const updateResult = await query(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashedNewPassword, user.id]
    );
    console.log("updateResult", updateResult);
    res.status(204).send("User updated");
  } catch (e) {
    res.status(500).send("Error updating user");
  }
});

app.delete("/users", async (req, res) => {
  const { username } = req.body;

  try {
    const deleteResult = await query("DELETE FROM users WHERE username = ?", [
      username,
    ]);
    console.log("deleteResult", deleteResult);
    res.send("User deleted");
  } catch (e) {
    res.status(500).send("Error deleting user");
  }
});

app.listen(port, () => {
  console.log("Listening on port: " + port);
});
