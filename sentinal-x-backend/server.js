const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const sodium = require('libsodium-wrappers');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});
// Initialize SQLite database
const db = new sqlite3.Database(':memory:'); // Use :memory: for dev, file for production

db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, publicKey TEXT)");
  db.run("CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, recipient_id INTEGER, ciphertext TEXT, iv TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
});

// Generate key pair for server
const serverKeys = {
  publicKey: null,
  privateKey: null
};

sodium.ready.then(() => {
  const keypair = sodium.crypto_box_keypair();
  serverKeys.publicKey = sodium.to_base64(keypair.publicKey);
  serverKeys.privateKey = sodium.to_base64(keypair.privateKey);
  console.log('Server keys generated');
});

// Socket.IO connection handler
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  // User registration
  socket.on('register', async ({ username, publicKey }, callback) => {
    try {
      db.run("INSERT INTO users (username, publicKey) VALUES (?, ?)", 
        [username, publicKey], 
        function(err) {
          if (err) {
            callback({ success: false, error: err.message });
            return;
          }
          callback({ success: true, userId: this.lastID });
          console.log(`User registered: ${username}`);
        }
      );
    } catch (error) {
      callback({ success: false, error: error.message });
    }
  });

  // Get online users
  socket.on('getUsers', (callback) => {
    db.all("SELECT id, username, publicKey FROM users", [], (err, rows) => {
      if (err) {
        callback({ success: false, error: err.message });
        return;
      }
      callback({ success: true, users: rows });
    });
  });

  // Send message
  socket.on('sendMessage', ({ senderId, recipientId, ciphertext, iv }, callback) => {
    const timestamp = new Date().toISOString();
    db.run(
      "INSERT INTO messages (sender_id, recipient_id, ciphertext, iv, timestamp) VALUES (?, ?, ?, ?, ?)",
      [senderId, recipientId, ciphertext, iv, timestamp],
      function(err) {
        if (err) {
          callback({ success: false, error: err.message });
          return;
        }
        
        // Notify recipient
        io.to(recipientId).emit('newMessage', {
          messageId: this.lastID,
          senderId,
          ciphertext,
          iv,
          timestamp
        });
        
        callback({ success: true });
      }
    );
  });

  // Disconnect handler
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
