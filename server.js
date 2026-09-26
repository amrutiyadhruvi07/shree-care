// Run command: node server.js

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));

const SECRET_KEY = "shreecare_super_secret";

// --- BULLETPROOF DATABASE SETUP ---
const db = new sqlite3.Database("./shreecare.sqlite");
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT)`,
  );
  db.run(
    `CREATE TABLE IF NOT EXISTS medicines (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL, stock INTEGER)`,
  );
  db.run(
    `CREATE TABLE IF NOT EXISTS appointments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, doctor_name TEXT, date TEXT, status TEXT)`,
  );
  db.run(
    `CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, total REAL, items TEXT, date TEXT)`,
  );
  db.run(
    `CREATE TABLE IF NOT EXISTS doctors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, specialty TEXT)`,
  );

  // Create Default Admin
  db.get("SELECT COUNT(*) AS count FROM users", async (err, row) => {
    if (!err && row && row.count === 0) {
      const adminPass = await bcrypt.hash("admin123", 10);
      db.run(
        `INSERT INTO users (username, password, role) VALUES ('admin', '${adminPass}', 'admin')`,
      );
    }
  });

  // Create Default Doctors
  db.get("SELECT COUNT(*) AS count FROM doctors", (err, row) => {
    if (!err && row && row.count === 0) {
      db.run(
        `INSERT INTO doctors (name, specialty) VALUES ('Dr. Sharma', 'Cardiologist')`,
      );
      db.run(
        `INSERT INTO doctors (name, specialty) VALUES ('Dr. Patel', 'General Physician')`,
      );
      db.run(
        `INSERT INTO doctors (name, specialty) VALUES ('Dr. Singh', 'Dermatologist')`,
      );
    }
  });
});

const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ error: "Please log in." });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Session expired." });
    req.user = decoded;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Admin only." });
  next();
};

// --- AUTH API ---
app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run(
    `INSERT INTO users (username, password, role) VALUES (?, ?, 'user')`,
    [username, hash],
    function (err) {
      if (err) return res.status(400).json({ error: "Username taken." });
      res.json({ message: "Registration successful!" });
    },
  );
});

app.post("/api/auth/login", (req, res) => {
  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [req.body.username],
    async (err, user) => {
      if (!user || !(await bcrypt.compare(req.body.password, user.password)))
        return res.status(401).json({ error: "Invalid credentials." });
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        SECRET_KEY,
        { expiresIn: "2h" },
      );
      res.json({
        message: "Login successful!",
        token,
        role: user.role,
        username: user.username,
      });
    },
  );
});

// --- PUBLIC & HISTORY API ---
app.get("/api/medicines", (req, res) =>
  db.all(`SELECT * FROM medicines`, [], (err, rows) => res.json(rows || [])),
);
app.get("/api/doctors", (req, res) =>
  db.all(`SELECT * FROM doctors`, [], (err, rows) => res.json(rows || [])),
);
app.get("/api/my-appointments", authenticate, (req, res) =>
  db.all(
    `SELECT * FROM appointments WHERE user_id = ? ORDER BY id DESC`,
    [req.user.id],
    (err, rows) => res.json(rows || []),
  ),
);
app.get("/api/my-orders", authenticate, (req, res) =>
  db.all(
    `SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC`,
    [req.user.id],
    (err, rows) => res.json(rows || []),
  ),
);

app.post("/api/appointments", authenticate, (req, res) => {
  db.run(
    `INSERT INTO appointments (user_id, doctor_name, date, status) VALUES (?, ?, ?, 'Pending')`,
    [req.user.id, req.body.doctor_name, req.body.date],
    () => res.json({ message: "Booked!" }),
  );
});
app.post("/api/checkout", authenticate, (req, res) => {
  req.body.cartItems.forEach((item) =>
    db.run(`UPDATE medicines SET stock = stock - ? WHERE id = ?`, [
      item.qty,
      item.id,
    ]),
  );
  const itemsJson = JSON.stringify(req.body.cartItems);
  db.run(
    `INSERT INTO orders (user_id, total, items, date) VALUES (?, ?, ?, ?)`,
    [req.user.id, req.body.total, itemsJson, new Date().toLocaleString()],
    () => res.json({ message: "Payment Successful!" }),
  );
});

// --- ADMIN API ---
app.get("/api/admin/stats", authenticate, isAdmin, (req, res) => {
  db.get(`SELECT COUNT(*) as users FROM users WHERE role='user'`, (err, u) => {
    db.get(`SELECT COUNT(*) as appts FROM appointments`, (err, a) => {
      db.get(`SELECT SUM(total) as revenue FROM orders`, (err, o) => {
        res.json({
          users: u ? u.users : 0,
          appts: a ? a.appts : 0,
          revenue: o && o.revenue ? o.revenue : 0,
        });
      });
    });
  });
});

// Medicines
app.post("/api/admin/medicines", authenticate, isAdmin, (req, res) =>
  db.run(
    `INSERT INTO medicines (name, price, stock) VALUES (?, ?, ?)`,
    [req.body.name, req.body.price, req.body.stock],
    () => res.json({ message: "Added!" }),
  ),
);
app.put("/api/admin/medicines/:id", authenticate, isAdmin, (req, res) =>
  db.run(
    `UPDATE medicines SET price = ?, stock = ? WHERE id = ?`,
    [req.body.price, req.body.stock, req.params.id],
    () => res.json({ message: "Updated!" }),
  ),
);
app.delete("/api/admin/medicines/:id", authenticate, isAdmin, (req, res) =>
  db.run(`DELETE FROM medicines WHERE id = ?`, [req.params.id], () =>
    res.json({ message: "Deleted!" }),
  ),
);

// Doctors (With Error Handling)
app.post("/api/admin/doctors", authenticate, isAdmin, (req, res) => {
  db.run(
    `INSERT INTO doctors (name, specialty) VALUES (?, ?)`,
    [req.body.name, req.body.specialty],
    function (err) {
      if (err) return res.status(500).json({ error: "Database error" });
      res.json({ message: "Doctor Added!" });
    },
  );
});
app.put("/api/admin/doctors/:id", authenticate, isAdmin, (req, res) =>
  db.run(
    `UPDATE doctors SET name = ?, specialty = ? WHERE id = ?`,
    [req.body.name, req.body.specialty, req.params.id],
    () => res.json({ message: "Updated!" }),
  ),
);
app.delete("/api/admin/doctors/:id", authenticate, isAdmin, (req, res) =>
  db.run(`DELETE FROM doctors WHERE id = ?`, [req.params.id], () =>
    res.json({ message: "Deleted!" }),
  ),
);

// Appointments
app.get("/api/admin/appointments", authenticate, isAdmin, (req, res) => {
  db.all(
    `SELECT appointments.*, COALESCE(users.username, 'Unknown User') as username FROM appointments LEFT JOIN users ON appointments.user_id = users.id`,
    [],
    (err, rows) => res.json(rows || []),
  );
});
app.put("/api/admin/appointments/:id", authenticate, isAdmin, (req, res) =>
  db.run(
    `UPDATE appointments SET status = ? WHERE id = ?`,
    [req.body.status, req.params.id],
    () => res.json({ message: "Updated!" }),
  ),
);
app.delete("/api/admin/appointments/:id", authenticate, isAdmin, (req, res) =>
  db.run(`DELETE FROM appointments WHERE id = ?`, [req.params.id], () =>
    res.json({ message: "Deleted!" }),
  ),
);

app.listen(3000, () => console.log(`Server running on http://localhost:3000`));
