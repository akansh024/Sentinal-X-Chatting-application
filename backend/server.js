require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const socketio = require('socket.io');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const { createTerminus } = require('@godaddy/terminus');

const authRoutes = require('./routes/auth.routes');
const chatRoutes = require('./routes/chat.routes');
const { initializeSocket } = require('./socket/chat.socket');
const errorHandler = require('./middleware/error.middleware');

const app = express();
const server = http.createServer(app);

// Validate environment variables
if (!process.env.JWT_SECRET || !process.env.MONGO_URI) {
  console.error('Fatal Error: Missing required environment variables');
  process.exit(1);
}

// Configure Socket.IO
const io = socketio(server, {
  cors: {
    origin: process.env.CLIENT_URL || '*',
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  pingInterval: 10000,
  pingTimeout: 5000
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: 'same-origin' }
}));

// CORS configuration
app.use(cors({
  origin: process.env.CLIENT_URL || '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Global rate limiter
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  message: 'Too many requests. Please try again later.',
  standardHeaders: true
}));

// Body parsing and sanitization
app.use(express.json({ limit: '10kb' }));
app.use(mongoSanitize());
app.use(compression());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err.message);
  process.exit(1);
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/chat', chatRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'UP',
    database: mongoose.connection.readyState === 1 ? 'CONNECTED' : 'DISCONNECTED'
  });
});

// Default route
app.get('/', (req, res) => {
  res.send(`${process.env.APP_NAME || 'Sentinal-X'} API is running`);
});

// Initialize Socket.IO
initializeSocket(io);

// Centralized error handling
app.use(errorHandler);

// Graceful shutdown
createTerminus(server, {
  signals: ['SIGINT', 'SIGTERM'],
  timeout: 10000,
  onSignal: () => {
    console.log('Server is starting cleanup');
    return Promise.all([
      mongoose.disconnect(),
      new Promise(resolve => io.close(resolve))
    ]);
  },
  onShutdown: () => console.log('Cleanup finished. Server is shutting down')
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`MongoDB URI: ${process.env.MONGO_URI}`);
  console.log(`JWT Expiry: ${process.env.TOKEN_EXPIRY || '7d'}`);
  console.log(`App Name: ${process.env.APP_NAME || 'Sentinal-X'}`);
});
