const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

app.use(cors({
  origin: ["http://localhost:3000", "https://fitplay-app.vercel.app"],
  credentials: true,
}));
app.use(bodyParser.json());

// Подключение к MongoDB
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });

// Схема пользователя
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  fullname: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatarUrl: { type: String },
});

const User = mongoose.model("User", UserSchema);

// Регистрация
app.post("/api/register", async (req, res) => {
  const { email, fullname, username, password, avatarUrl } = req.body;

  if (!email || !fullname || !username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      email,
      fullname,
      username,
      password: hashedPassword,
      avatarUrl,
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully", _id: newUser._id });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Failed to register user", error: error.message });
  }
});

// Логин
app.post("/api/login", async (req, res) => {
  const { password, username } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json("Invalid username or password");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json("Invalid username or password");
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ token, user });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json("Internal server error");
  }
});

// Пример защищенного маршрута
app.get("/api/profile/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json("User not found");
    }
    res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json("Internal server error");
  }
});

// Обновление аватарки пользователя
app.patch("/api/users/:id", async (req, res) => {
  const { avatarUrl } = req.body;
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { avatarUrl },
      { new: true }
    );
    if (!user) {
      return res.status(404).json("User not found");
    }
    res.status(200).json(user);
  } catch (error) {
    console.error("Error updating avatar:", error);
    res.status(500).json("Internal server error");
  }
});

// Экспортируем приложение
module.exports = app;
