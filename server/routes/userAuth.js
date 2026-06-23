const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'scamshield2024superSecretKey123';
const JWT_EXPIRES = '30d';

// ─── POST /api/auth/signup ────────────────────────────────────
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password, full_name } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ ok: false, err: 'Username, email, and password are required.' });
    }
    if (username.length < 3) {
      return res.status(400).json({ ok: false, err: 'Username must be at least 3 characters.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ ok: false, err: 'Password must be at least 6 characters.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ ok: false, err: 'Invalid email address.' });
    }

    // Check if user exists
    const existing = await User.findOne({
      $or: [{ username }, { email: email.toLowerCase() }]
    });
    if (existing) {
      const field = existing.username === username ? 'Username' : 'Email';
      return res.status(400).json({ ok: false, err: `${field} already exists.` });
    }

    // Create user
    const user = new User({
      username,
      email: email.toLowerCase(),
      password_hash: password, // pre-save hook will hash it
      full_name: full_name || username
    });
    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { user_id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      ok: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        full_name: user.full_name
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ ok: false, err: 'Failed to create account.' });
  }
});

// ─── POST /api/auth/login ─────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ ok: false, err: 'Username and password are required.' });
    }

    // Find user by username or email
    const user = await User.findOne({
      $or: [{ username }, { email: username.toLowerCase() }]
    });

    if (!user) {
      return res.status(401).json({ ok: false, err: 'Invalid username or password.' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ ok: false, err: 'Invalid username or password.' });
    }

    // Update last login
    user.last_login = new Date();
    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { user_id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      ok: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        full_name: user.full_name,
        total_attempts: user.total_attempts,
        total_modules_completed: user.total_modules_completed
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ ok: false, err: 'Login failed. Please try again.' });
  }
});

// ─── GET /api/auth/me ─────────────────────────────────────────
router.get('/me', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ ok: false, err: 'No token provided.' });
    }

    const token = authHeader.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const user = await User.findById(decoded.user_id).select('-password_hash');
    if (!user) {
      return res.status(401).json({ ok: false, err: 'User not found.' });
    }

    res.json({ ok: true, user });
  } catch (error) {
    console.error('Auth check error:', error);
    res.status(401).json({ ok: false, err: 'Invalid token.' });
  }
});

module.exports = router;