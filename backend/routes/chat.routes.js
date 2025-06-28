const express = require('express');
const router = express.Router();
const messageController = require('../controllers/message.controller');
const authMiddleware = require('../middlewares/auth.middleware');
const rateLimit = require('express-rate-limit');
const { body, param } = require('express-validator');

// Rate limiting for message sending
const messageLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 15, // Max 15 messages per minute per user
    keyGenerator: (req) => req.user.userId, // Limit by user ID
    message: 'Too many messages. Please slow down.',
    standardHeaders: true,
    legacyHeaders: false
});

// Message validation
const sendMessageValidation = [
    body('receiver')
        .isMongoId()
        .withMessage('Invalid receiver ID format'),
    
    body('text')
        .trim()
        .notEmpty()
        .withMessage('Message text is required')
        .isLength({ max: 2000 })
        .withMessage('Message cannot exceed 2000 characters')
];

// Message ID validation
const messageIdValidation = [
    param('id')
        .isMongoId()
        .withMessage('Invalid message ID format')
];

// Conversation validation
const conversationValidation = [
    param('user1')
        .isMongoId()
        .withMessage('Invalid user ID format'),
    
    param('user2')
        .isMongoId()
        .withMessage('Invalid user ID format'),
    
    body().custom((value, { req }) => {
        if (req.user.userId !== req.params.user1 && req.user.userId !== req.params.user2) {
            throw new Error('Unauthorized to access this conversation');
        }
        return true;
    })
];

// Pagination validation
const paginationValidation = [
    body('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),
    
    body('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100')
];

// POST /api/chat/send - Send encrypted message
router.post(
    '/send',
    authMiddleware.verifyToken,
    messageLimiter,
    sendMessageValidation,
    messageController.sendMessage
);

// GET /api/chat/conversation/:user1/:user2 - Get conversation
router.get(
    '/conversation/:user1/:user2',
    authMiddleware.verifyToken,
    conversationValidation,
    paginationValidation,
    messageController.getConversation
);

// DELETE /api/chat/:id - Soft delete message
router.delete(
    '/:id',
    authMiddleware.verifyToken,
    messageIdValidation,
    messageController.deleteMessage
);

// PATCH /api/chat/:id/read - Mark message as read
router.patch(
    '/:id/read',
    authMiddleware.verifyToken,
    messageIdValidation,
    messageController.markAsRead
);

// PATCH /api/chat/:id - Edit message
router.patch(
    '/:id',
    authMiddleware.verifyToken,
    messageIdValidation,
    [
        body('text')
            .trim()
            .notEmpty()
            .withMessage('Message text is required')
            .isLength({ max: 2000 })
            .withMessage('Message cannot exceed 2000 characters')
    ],
    messageController.editMessage
);

// GET /api/chat/unread-count - Get unread message count
router.get(
    '/unread-count',
    authMiddleware.verifyToken,
    messageController.getUnreadCount
);

// POST /api/chat/report/:id - Report a message
router.post(
    '/report/:id',
    authMiddleware.verifyToken,
    messageIdValidation,
    [
        body('reason')
            .isIn(['spam', 'harassment', 'inappropriate', 'other'])
            .withMessage('Invalid report reason')
    ],
    messageController.reportMessage
);

module.exports = router;