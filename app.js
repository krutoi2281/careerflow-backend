const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const pool = require("./db");
const auth = require("./middleware/auth");

const app = express();

app.use(cors());
app.use(express.json());

function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      ok: true,
      message: "CareerFlow backend работает",
      time: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Заполни name, email и password"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        message: "Эта почта уже зарегистрирована. Войди в существующий аккаунт."
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, role, language, theme, created_at`,
      [name.trim(), normalizedEmail, passwordHash, role || "job_seeker"]
    );

    const user = result.rows[0];
    const token = generateToken(user);

    res.status(201).json({
      message: "Регистрация успешна",
      token,
      user
    });
  } catch (error) {
    res.status(500).json({
      message: "Ошибка сервера",
      error: error.message
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Введи email и password"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Неверная почта или пароль"
      });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({
        message: "Неверная почта или пароль"
      });
    }

    const token = generateToken(user);

    res.json({
      message: "Вход выполнен",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        language: user.language,
        theme: user.theme,
        created_at: user.created_at
      }
    });
  } catch (error) {
    res.status(500).json({
      message: "Ошибка сервера",
      error: error.message
    });
  }
});

app.get("/api/user/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role, language, theme, created_at
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: "Пользователь не найден"
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({
      message: "Ошибка сервера",
      error: error.message
    });
  }
});

app.put("/api/user/settings", auth, async (req, res) => {
  try {
    const { language, theme } = req.body;

    const result = await pool.query(
      `UPDATE users
       SET language = COALESCE($1, language),
           theme = COALESCE($2, theme)
       WHERE id = $3
       RETURNING id, name, email, role, language, theme, created_at`,
      [language || null, theme || null, req.user.id]
    );

    res.json({
      message: "Настройки обновлены",
      user: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      message: "Ошибка сервера",
      error: error.message
    });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, role, language, theme, created_at FROM users ORDER BY id DESC"
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      message: "Ошибка сервера",
      error: error.message
    });
  }
});

const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server started on port " + PORT);
});
