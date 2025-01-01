const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const expressValidator = require('express-validator');

// Load environment variables
dotenv.config();

// Initialize the app
const app = express();

// Middleware
app.use(helmet());  // Apply security headers like X-XSS-Protection, X-Frame-Options
app.use(bodyParser.json());
app.use(cookieParser());
app.use(expressValidator()); // Add express-validator for input validation and sanitization

// CSRF Protection Middleware
const csrfProtection = csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'Strict' } });
app.use(csrfProtection);

// Rate limiting to prevent brute-force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,  // Limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.'
});
app.use(limiter);

// MongoDB connection with authentication
mongoose.connect(process.env.MONGODB_URI, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true,
  auth: { user: process.env.MONGO_USER, password: process.env.MONGO_PASS }
})
  .then(() => console.log('MongoDB connected securely'))
  .catch((err) => console.log('MongoDB connection error:', err));

// Define the user model
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }  // Role-based access control (RBAC)
}));

// User registration route
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  // Validate input with express-validator
  req.checkBody('email', 'Invalid email').isEmail();
  req.checkBody('password', 'Password is required').notEmpty();
  const errors = req.validationErrors();
  if (errors) {
    return res.status(400).json({ errors });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    // Hash password with bcrypt
    const hashedPassword = await bcrypt.hash(password, 12);  // Salt rounds of 12
    const newUser = new User({ email, password: hashedPassword });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// User login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Compare password with bcrypt
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Generate JWT token with user role
    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Set JWT token in HttpOnly cookie (to prevent XSS attacks)
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
    res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Logout route
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.status(200).json({ message: 'Logout successful' });
});

// Secure route with role-based access control (RBAC)
app.get('/api/protected', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: 'Access denied, please login first.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }

    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: 'You do not have access to this resource' });
    }

    res.status(200).json({ message: 'Welcome Admin' });
  });
});

// Serve the CSRF token to frontend
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Start the server with HTTPS (For production, you'll need an SSL certificate)
const https = require('https');
const fs = require('fs');

// Replace 'path_to_cert' with actual paths to SSL certificate files
const options = {
  key: fs.readFileSync('path_to_key.pem'),
  cert: fs.readFileSync('path_to_cert.pem')
};

const port = process.env.PORT || 5000;
https.createServer(options, app).listen(port, () => {
  console.log(`Server running securely on https://localhost:${port}`);
});
