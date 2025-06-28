const mongoose = require('mongoose');
const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf } = format;

// Create a logger for database operations
const dbLogger = createLogger({
  level: 'info',
  format: combine(
    timestamp(),
    printf(({ level, message, timestamp }) => {
      return `${timestamp} [DB] ${level}: ${message}`;
    })
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'logs/db.log' })
  ]
});

// Connection state tracking
let isConnected = false;
let connectionRetries = 0;
const MAX_RETRIES = 5;
const RETRY_INTERVAL = 5000; // 5 seconds

// Connection event handlers
const setConnectionHandlers = (conn) => {
  conn.on('connected', () => {
    isConnected = true;
    connectionRetries = 0;
    dbLogger.info(`MongoDB connected to ${conn.host}:${conn.port}/${conn.name}`);
  });

  conn.on('disconnected', () => {
    isConnected = false;
    dbLogger.warn('MongoDB disconnected');
  });

  conn.on('reconnected', () => {
    isConnected = true;
    dbLogger.info('MongoDB reconnected');
  });

  conn.on('error', (err) => {
    dbLogger.error(`MongoDB connection error: ${err.message}`);
  });
};

// Connect to MongoDB with retry logic
const connectDB = async () => {
  // Return existing connection if available
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      autoIndex: process.env.NODE_ENV !== 'production',
      maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
      minPoolSize: parseInt(process.env.DB_MIN_POOL_SIZE) || 2,
      serverSelectionTimeoutMS: parseInt(process.env.DB_SERVER_SELECTION_TIMEOUT) || 5000,
      socketTimeoutMS: parseInt(process.env.DB_SOCKET_TIMEOUT) || 45000,
      family: 4,
      heartbeatFrequencyMS: process.env.NODE_ENV === 'production' ? 10000 : 30000,
      retryWrites: true,
      w: 'majority'
    });

    setConnectionHandlers(conn.connection);
    return conn;
  } catch (err) {
    dbLogger.error(`Initial connection failed: ${err.message}`);
    
    // Implement retry logic
    if (connectionRetries < MAX_RETRIES) {
      connectionRetries++;
      dbLogger.warn(`Retrying connection (${connectionRetries}/${MAX_RETRIES}) in ${RETRY_INTERVAL/1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, RETRY_INTERVAL));
      return connectDB();
    } else {
      dbLogger.error('Maximum connection retries reached. Exiting process.');
      process.exit(1);
    }
  }
};

// Graceful shutdown handler
const gracefulShutdown = async (signal) => {
  dbLogger.info(`Received ${signal}. Closing MongoDB connection...`);
  try {
    await mongoose.disconnect();
    dbLogger.info('MongoDB connection closed successfully');
    process.exit(0);
  } catch (err) {
    dbLogger.error(`Error closing MongoDB connection: ${err.message}`);
    process.exit(1);
  }
};

// Handle process termination signals
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Health check function
const checkDatabaseHealth = async () => {
  try {
    const result = await mongoose.connection.db.admin().ping();
    return {
      status: 'UP',
      database: 'MongoDB',
      ping: result.ok === 1 ? 'OK' : 'FAILED',
      connectionState: mongoose.STATES[mongoose.connection.readyState],
      uptime: process.uptime(),
      details: {
        host: mongoose.connection.host,
        port: mongoose.connection.port,
        database: mongoose.connection.name,
        models: Object.keys(mongoose.connection.models)
      }
    };
  } catch (err) {
    return {
      status: 'DOWN',
      error: err.message,
      connectionState: mongoose.STATES[mongoose.connection.readyState]
    };
  }
};

module.exports = {
  connectDB,
  checkDatabaseHealth,
  isConnected: () => isConnected,
  getConnection: () => mongoose.connection
};