const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

// Validate environment configuration
if (!process.env.JWT_SECRET) {
    throw new Error('Missing JWT_SECRET environment variable');
}
const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_EXPIRY = process.env.TOKEN_EXPIRY || '7d';

// Password complexity requirements
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
const PASSWORD_ERROR_MESSAGE = 'Password must contain at least: 8 characters, 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character';

// Register new user
exports.register = async (req, res) => {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    if (!PASSWORD_REGEX.test(password)) {
        return res.status(400).json({ 
            message: PASSWORD_ERROR_MESSAGE,
            requirements: {
                minLength: 8,
                uppercase: 1,
                lowercase: 1,
                number: 1,
                specialChar: 1
            }
        });
    }

    try {
        // Check for existing user
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ message: 'Username is already taken' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Create and save user
        const newUser = new User({ 
            username, 
            password: hashedPassword,
            lastLogin: new Date()
        });
        
        await newUser.save();

        // Omit password from response
        const userResponse = {
            id: newUser._id,
            username: newUser.username,
            createdAt: newUser.createdAt
        };

        res.status(201).json({ 
            message: 'User registered successfully',
            user: userResponse
        });
    } catch (err) {
        console.error(`Registration Error [${username}]:`, err);
        res.status(500).json({ message: 'Registration failed. Please try again later.' });
    }
};

// Login user
exports.login = async (req, res) => {
    const { username, password } = req.body;
    const errorMessage = 'Invalid username or password';
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        // Find user with timing attack protection
        const user = await User.findOne({ username }).select('+password');
        
        // Security: Constant-time comparison
        let isMatch = false;
        if (user) {
            isMatch = await bcrypt.compare(password, user.password);
            user.lastLogin = new Date();
            await user.save();
        }

        if (!user || !isMatch) {
            console.warn(`Login Attempt Failed [${username}]: Invalid credentials from IP ${req.ip}`);
            return res.status(401).json({ message: errorMessage });
        }

        // Generate JWT
        const token = jwt.sign(
            { 
                userId: user._id,
                role: user.role || 'user' 
            },
            JWT_SECRET,
            {
                expiresIn: TOKEN_EXPIRY,
                issuer: process.env.APP_NAME || 'your-app',
                algorithm: 'HS256'
            }
        );

        // Prepare user response
        const userResponse = {
            id: user._id,
            username: user.username,
            role: user.role,
            lastLogin: user.lastLogin
        };

        res.status(200).json({ 
            message: 'Login successful',
            token,
            user: userResponse
        });
    } catch (err) {
        console.error(`Login Error [${username}]:`, err);
        res.status(500).json({ message: 'Authentication service unavailable. Please try again later.' });
    }
};

// Token verification middleware
exports.verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Missing or invalid authorization token' });
    }

    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.warn('JWT Verification Failed:', err.message);
            return res.status(401).json({ message: 'Invalid or expired token' });
        }
        
        req.user = {
            userId: decoded.userId,
            role: decoded.role
        };
        next();
    });
};

// Role-based access control middleware
exports.authorize = (roles = []) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        
        if (roles.length > 0 && !roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Insufficient permissions' });
        }
        
        next();
    };
};