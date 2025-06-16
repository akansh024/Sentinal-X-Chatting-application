const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const sodium = require('libsodium-wrappers');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// In-memory user-socket mapping for basic auth & messaging
const userSocketMap = new Map();

// Initialize SQLite database
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, publicKey TEXT)");
  db.run("CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, recipient_id INTEGER, ciphertext TEXT, iv TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
});

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

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  socket.on('register', async ({ username, password, publicKey }, callback) => {
    try {
      const salt = bcrypt.genSaltSync(10);
      const passwordHash = bcrypt.hashSync(password, salt);

      db.run("INSERT INTO users (username, password_hash, publicKey) VALUES (?, ?, ?)",
        [username, passwordHash, publicKey],
        function(err) {
          if (err) {
            callback({ success: false, error: err.message });
            return;
          }

          const userId = this.lastID;
          userSocketMap.set(userId, socket.id);
          socket.userId = userId;
          socket.join(userId.toString());

          callback({ success: true, userId });
          console.log(`User registered: ${username}`);
        }
      );
    } catch (error) {
      callback({ success: false, error: error.message });
    }
  });

  socket.on('login', ({ username, password }, callback) => {
    db.get("SELECT id, password_hash FROM users WHERE username = ?", [username], (err, row) => {
      if (err || !row) {
        callback({ success: false, error: 'Invalid username or password' });
        return;
      }

      if (bcrypt.compareSync(password, row.password_hash)) {
        userSocketMap.set(row.id, socket.id);
        socket.userId = row.id;
        socket.join(row.id.toString());
        callback({ success: true, userId: row.id });
        console.log(`User logged in: ${username}`);
      } else {
        callback({ success: false, error: 'Invalid username or password' });
      }
    });
  });

  socket.on('getUsers', (callback) => {
    db.all("SELECT id, username, publicKey FROM users", [], (err, rows) => {
      if (err) {
        callback({ success: false, error: err.message });
        return;
      }
      callback({ success: true, users: rows });
    });
  });

  socket.on('sendMessage', ({ senderId, recipientId, ciphertext, iv }, callback) => {
    if (socket.userId !== senderId) {
      callback({ success: false, error: 'Unauthorized sender' });
      return;
    }

    const timestamp = new Date().toISOString();
    db.run(
      "INSERT INTO messages (sender_id, recipient_id, ciphertext, iv, timestamp) VALUES (?, ?, ?, ?, ?)",
      [senderId, recipientId, ciphertext, iv, timestamp],
      function(err) {
        if (err) {
          callback({ success: false, error: err.message });
          return;
        }

        io.to(recipientId.toString()).emit('newMessage', {
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

  socket.on('getMessages', ({ userId, contactId }, callback) => {
    db.all(
      `SELECT * FROM messages
       WHERE (sender_id = ? AND recipient_id = ?)
          OR (sender_id = ? AND recipient_id = ?)
       ORDER BY timestamp ASC`,
      [userId, contactId, contactId, userId],
      (err, rows) => {
        if (err) {
          callback({ success: false, error: err.message });
        } else {
          callback({ success: true, messages: rows });
        }
      }
    );
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      userSocketMap.delete(socket.userId);
    }
    console.log('Client disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
