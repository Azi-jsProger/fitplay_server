const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 8888;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

const corsOptions = {
  origin: ["http://localhost:3000", "https://fitplay-app.vercel.app",""],

  credentials: true,
};

app.use(cors(corsOptions));
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
  avatarUrl: { type: String }, // Поле для URL аватарки
});

// Уникальные индексы для email и username
UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ username: 1 }, { unique: true });

const User = mongoose.model("User", UserSchema);

app.post("/register", async (req, res) => {
  const { email, fullname, username, password, avatarUrl } = req.body;

  console.log("Request body:", req.body); // Логирование

  // Проверка на обязательные поля
  if (!email || !fullname || !username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "User with this username or email already exists" });
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
    res
      .status(201)
      .json({ message: "User registered successfully", _id: newUser._id });
  } catch (error) {
    console.error("Error registering user:", error);
    if (error.code === 11000) {
      return res
        .status(400)
        .json({ message: "Duplicate key error", error: error.message });
    }
    res
      .status(500)
      .json({
        message: "Failed to register user",
        error: error.message || error,
      });
  }
});

// Авторизация пользователя
app.post("/login", async (req, res) => {
  const { password, username } = req.body;

  try {
    // Поиск пользователя по имени пользователя
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json("Invalid username or password");
    }

    // Сравниваем хэшированный пароль
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json("Invalid username or password");
    }

    // Генерация токена JWT
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res.status(200).json({ token, user });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json("Internal server error");
  }
});

// Middleware для проверки токена
function authenticateToken(req, res, next) {
  const token =
    req.headers["authorization"] && req.headers["authorization"].split(" ")[1];
  if (!token) {
    return res.status(401).json("Access denied");
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json("Invalid token");
    }
    req.user = user;
    next();
  });
}

// Пример защищенного маршрута
app.get("/profile/:id", authenticateToken, async (req, res) => {
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
app.patch("/users/:id", authenticateToken, async (req, res) => {
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

// Запуск сервера
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
