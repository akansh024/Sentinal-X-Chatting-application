const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const rateLimit = require('express-rate-limit');
const { body } = require('express-validator');
const authMiddleware = require('../middleware/auth.middleware');

// Strict rate limiting for authentication endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 requests per window
    message: 'Too many requests from this IP. Please try again later.',
    standardHeaders: true, // Return rate limit info in headers
    legacyHeaders: false, // Disable legacy headers
    skipSuccessfulRequests: true // Only count failed requests
});

// Registration validation
const registerValidation = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be 3-30 characters')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username can only contain letters, numbers and underscores'),

    body('email')
        .trim()
        .normalizeEmail()
        .isEmail()
        .withMessage('Please provide a valid email'),

    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
        .withMessage('Password must contain at least: 1 uppercase, 1 lowercase, 1 number, and 1 special character'),

    body('confirmPassword')
        .custom((value, { req }) => value === req.body.password)
        .withMessage('Passwords do not match')
];

// Login validation
const loginValidation = [
    body('username')
        .trim()
        .notEmpty()
        .withMessage('Username is required'),

    body('password')
        .notEmpty()
        .withMessage('Password is required')
];

// POST /api/auth/register
router.post(
    '/register', 
    authLimiter,
    registerValidation,
    authController.register
);

// POST /api/auth/login
router.post(
    '/login', 
    authLimiter,
    loginValidation,
    authController.login
);

// POST /api/auth/refresh-token
router.post(
    '/refresh-token',
    authController.refreshToken
);

// POST /api/auth/logout
router.post(
    '/logout',
    authMiddleware.verifyToken,
    authController.logout
);

// POST /api/auth/verify-email
router.post(
    '/verify-email',
    [
        body('token')
            .notEmpty()
            .withMessage('Verification token is required')
    ],
    authController.verifyEmail
);

// POST /api/auth/forgot-password
router.post(
    '/forgot-password',
    [
        body('email')
            .trim()
            .normalizeEmail()
            .isEmail()
            .withMessage('Please provide a valid email')
    ],
    authController.forgotPassword
);

// POST /api/auth/reset-password
router.post(
    '/reset-password',
    [
        body('token')
            .notEmpty()
            .withMessage('Reset token is required'),

        body('newPassword')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters')
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
            .withMessage('Password must contain at least: 1 uppercase, 1 lowercase, 1 number, and 1 special character'),

        body('confirmPassword')
            .custom((value, { req }) => value === req.body.newPassword)
            .withMessage('Passwords do not match')
    ],
    authController.resetPassword
);

// GET /api/auth/validate-token
router.get(
    '/validate-token',
    authMiddleware.verifyToken,
    (req, res) => {
        res.status(200).json({ valid: true, user: req.user });
    }
);

module.exports = router;
