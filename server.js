const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 8888;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Настройка CORS
const corsOptions = {
    origin: ['http://localhost:3000', 'https://my-project-4fcfdlrgd-azi-progerjs-projects.vercel.app'],
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(bodyParser.json());

// Подключение к MongoDB
mongoose.connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.error('Error connecting to MongoDB:', error);
});

// Модель пользователя
const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    speciality: String,
    login: String,
    role: { type: String, default: 'user' }
});

const User = mongoose.model('User', UserSchema);

// Регистрация пользователя
app.post('/register', async (req, res) => {
    const { username, password, login, speciality } = req.body;

    try {
        const existingUser = await User.findOne({ login });
        if (existingUser) {
            return res.status(400).json('User already exists');
        }

        // Хешируем пароль
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ username, password: hashedPassword, login, speciality });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully', _id: newUser._id });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json('Failed to register user');
    }
});

app.post('/login', async (req, res) => {
    const { password, login } = req.body;

    try {
        // Ищем пользователя по логину
        const user = await User.findOne({ login });
        if (!user) {
            console.log('User not found');
            return res.status(400).json('Invalid login or password');
        }

        // Проверяем пароль
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Password mismatch');
            return res.status(400).json('Invalid login or password');
        }

        // Создаем токен
        const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ token, role: user.role, message: 'Login successful' });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json('Internal server error');
    }
});



// Middleware для проверки токена
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) {
        return res.status(401).json('Access denied');
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json('Invalid token');
        }
        req.user = user;
        next();
    });
}

// Получение профиля пользователя
app.get('/profile/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json('User not found');
        }
        res.json(user);
    } catch (error) {
        console.error('Error retrieving user data:', error);
        res.status(500).json('Error retrieving user data');
    }
});

// Список всех пользователей
app.get('/users', authenticateToken, async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (error) {
        console.error('Error retrieving users:', error);
        res.status(500).json('Error retrieving users');
    }
});

// Маршрут для обновления статуса пользователя
app.post('/update-status', authenticateToken, async (req, res) => {
    const { userId, isOnline } = req.body;

    try {
        const user = await User.findByIdAndUpdate(userId, { isOnline }, { new: true });
        if (!user) {
            return res.status(404).json('User not found');
        }
        res.json({ message: 'Status updated successfully', user });
    } catch (error) {
        console.error('Error updating status:', error);
        res.status(500).json('Failed to update status');
    }
});

// Запуск сервера
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

module.exports = app;
