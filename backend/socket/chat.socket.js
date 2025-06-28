const jwt = require('jsonwebtoken');
const Message = require('../models/message.model');
const User = require('../models/user.model');

// Track online users: userId => socketId
const onlineUsers = new Map();

// Store public keys: userId => publicKey
const userPublicKeys = new Map();

exports.initializeSocket = (io) => {
  // Authentication middleware
  io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication required'));

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Fetch user from database
      const user = await User.findById(decoded.userId);
      if (!user) return next(new Error('User not found'));
      
      socket.user = {
        userId: user._id.toString(),
        username: user.username,
        publicKey: user.publicKey
      };
      
      next();
    } catch (err) {
      next(new Error('Invalid or expired token'));
    }
  });

  io.on('connection', async (socket) => {
    console.log(`🔌 New connection: ${socket.id} (User: ${socket.user.username})`);

    // Add user to online list
    onlineUsers.set(socket.user.userId, socket.id);
    
    // Store user's public key
    if (socket.user.publicKey) {
      userPublicKeys.set(socket.user.userId, socket.user.publicKey);
    }
    
    // Notify others this user is online
    io.emit('userOnline', { 
      userId: socket.user.userId,
      username: socket.user.username
    });

    // Join user-specific room
    socket.join(`user_${socket.user.userId}`);
    socket.join('onlineUsers');

    // Send current online statuses
    socket.emit('onlineStatuses', Array.from(onlineUsers.keys()));

    // Handle key exchange
    socket.on('publicKey', (publicKey) => {
      if (publicKey) {
        userPublicKeys.set(socket.user.userId, publicKey);
        console.log(`🔑 Public key updated for user ${socket.user.username}`);
      }
    });

    // Handle incoming encrypted chat message
    socket.on('sendEncryptedMessage', async ({ receiverId, encryptedData }, callback) => {
      try {
        if (!receiverId || !encryptedData || 
            !encryptedData.cipher || !encryptedData.nonce) {
          throw new Error('Invalid encrypted message payload');
        }

        // Save encrypted message to database
        const message = new Message({
          sender: socket.user.userId,
          receiver: receiverId,
          text: {
            cipher: encryptedData.cipher,
            nonce: encryptedData.nonce,
            senderPublicKey: userPublicKeys.get(socket.user.userId)
          },
          status: 'sent'
        });

        await message.save();

        const messageData = {
          _id: message._id,
          sender: message.sender,
          receiver: message.receiver,
          text: message.text,
          createdAt: message.createdAt,
          status: 'sent'
        };

        // Emit to sender
        socket.emit('newEncryptedMessage', messageData);

        // Emit to receiver if online
        const receiverSocketId = onlineUsers.get(receiverId);
        if (receiverSocketId) {
          io.to(receiverSocketId).emit('newEncryptedMessage', messageData);
        }

        callback({ success: true, message: messageData });
      } catch (err) {
        console.error('Encrypted Message Error:', err.message);
        callback({ success: false, error: 'Failed to send encrypted message' });
      }
    });

    // Handle key request
    socket.on('requestPublicKey', ({ userId }, callback) => {
      try {
        const publicKey = userPublicKeys.get(userId);
        if (!publicKey) {
          throw new Error('Public key not available');
        }
        
        callback({ success: true, publicKey });
      } catch (err) {
        console.error('Public Key Request Error:', err.message);
        callback({ success: false, error: 'Could not retrieve public key' });
      }
    });

    // Handle read receipts
    socket.on('markAsRead', async (messageId) => {
      try {
        const updatedMessage = await Message.markAsRead(messageId, socket.user.userId);
        if (updatedMessage) {
          io.to(`user_${updatedMessage.sender}`).emit('messageRead', {
            messageId: updatedMessage._id,
            readAt: updatedMessage.readAt
          });
        }
      } catch (err) {
        console.error('Read Receipt Error:', err.message);
      }
    });

    // Handle typing indicators
    socket.on('typing', ({ receiverId }) => {
      const receiverSocketId = onlineUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('typing', {
          senderId: socket.user.userId,
          senderName: socket.user.username
        });
      }
    });

    socket.on('stopTyping', ({ receiverId }) => {
      const receiverSocketId = onlineUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('stopTyping', {
          senderId: socket.user.userId
        });
      }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      console.log(`🔥 Disconnected: ${socket.id} (${socket.user.username})`);
      
      // Remove from online users
      onlineUsers.delete(socket.user.userId);
      
      // Notify all users
      io.emit('userOffline', { userId: socket.user.userId });
    });

    // Handle socket errors
    socket.on('error', (err) => {
      console.error(`Socket Error (${socket.id}):`, err.message);
    });
  });
};