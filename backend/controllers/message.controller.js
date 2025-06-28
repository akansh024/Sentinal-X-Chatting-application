const crypto = require('crypto');
const Message = require('../models/message.model');

// Validate environment configuration
if (!process.env.MESSAGE_ENCRYPTION_KEY) {
    throw new Error('Missing MESSAGE_ENCRYPTION_KEY environment variable (32-byte key)');
}
const ENCRYPTION_KEY = process.env.MESSAGE_ENCRYPTION_KEY;
const IV_LENGTH = 16;
const ALGORITHM = 'aes-256-cbc';

// Encrypt text function
const encrypt = (text) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
};

// Decrypt text function
const decrypt = (text) => {
    const [ivPart, encryptedPart] = text.split(':');
    if (!ivPart || !encryptedPart) throw new Error('Invalid encrypted text format');
    
    const iv = Buffer.from(ivPart, 'hex');
    const encrypted = Buffer.from(encryptedPart, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString();
};

// Save new message
exports.sendMessage = async (req, res) => {
    const { sender, receiver, text } = req.body;

    // Input validation
    if (!sender || !receiver || !text) {
        return res.status(400).json({ message: "All fields are required" });
    }
    
    if (text.length > 1000) {
        return res.status(400).json({ message: "Message exceeds 1000 character limit" });
    }

    // Authorization check (user can only send as themselves)
    if (req.user.userId !== sender) {
        return res.status(403).json({ message: "Unauthorized to send messages as this user" });
    }

    try {
        // Encrypt message text
        const encryptedText = encrypt(text.trim());

        const newMsg = new Message({
            sender,
            receiver,
            text: encryptedText,
            timestamp: new Date(),
            status: 'sent'
        });

        await newMsg.save();
        
        // Return minimal information
        res.status(201).json({ 
            message: "Message sent",
            id: newMsg._id,
            timestamp: newMsg.timestamp
        });
    } catch (err) {
        console.error("Message Send Error:", err);
        res.status(500).json({ message: "Failed to send message" });
    }
};

// Get messages between two users
exports.getMessages = async (req, res) => {
    const { user1, user2 } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    // Authorization check (user can only access their own conversations)
    if (req.user.userId !== user1 && req.user.userId !== user2) {
        return res.status(403).json({ message: "Unauthorized to access this conversation" });
    }

    try {
        const [messages, totalCount] = await Promise.all([
            Message.find({
                $or: [
                    { sender: user1, receiver: user2 },
                    { sender: user2, receiver: user1 }
                ]
            })
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit)
            .lean(),
            
            Message.countDocuments({
                $or: [
                    { sender: user1, receiver: user2 },
                    { sender: user2, receiver: user1 }
                ]
            })
        ]);

        // Decrypt messages
        const decryptedMessages = messages.map(msg => {
            try {
                return {
                    ...msg,
                    text: decrypt(msg.text)
                };
            } catch (decryptErr) {
                console.error(`Decryption error for message ${msg._id}:`, decryptErr);
                return {
                    ...msg,
                    text: "Could not decrypt message"
                };
            }
        });

        res.status(200).json({
            messages: decryptedMessages,
            pagination: {
                page,
                limit,
                totalCount,
                totalPages: Math.ceil(totalCount / limit)
            }
        });
    } catch (err) {
        console.error("Message Fetch Error:", err);
        res.status(500).json({ message: "Failed to fetch messages" });
    }
};

// Message deletion (soft delete)
exports.deleteMessage = async (req, res) => {
    const { id } = req.params;

    try {
        const message = await Message.findById(id);
        if (!message) {
            return res.status(404).json({ message: "Message not found" });
        }

        // Authorization check (only sender or receiver can delete)
        if (message.sender.toString() !== req.user.userId && 
            message.receiver.toString() !== req.user.userId) {
            return res.status(403).json({ message: "Unauthorized to delete this message" });
        }

        // Soft delete implementation
        message.deleted = true;
        message.deletedBy = req.user.userId;
        message.deletedAt = new Date();
        
        await message.save();

        res.status(200).json({ message: "Message deleted" });
    } catch (err) {
        console.error("Message Delete Error:", err);
        res.status(500).json({ message: "Failed to delete message" });
    }
};