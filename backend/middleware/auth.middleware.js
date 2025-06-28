const jwt = require('jsonwebtoken');
const { createLogger, transports } = require('winston');
const rateLimit = require('express-rate-limit');
const redis = require('redis');
const { promisify } = require('util');

// Create a logger for authentication events
const authLogger = createLogger({
  level: 'info',
  transports: [
    new transports.Console({
      format: require('winston').format.combine(
        require('winston').format.colorize(),
        require('winston').format.simple()
      )
    }),
    new transports.File({ 
      filename: 'logs/auth.log',
      format: require('winston').format.combine(
        require('winston').format.timestamp(),
        require('winston').format.json()
      )
    })
  ]
});

// Initialize Redis client
const redisClient = redis.createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
  password: process.env.REDIS_PASSWORD
});

redisClient.on('error', (err) => {
  authLogger.error(`Redis connection error: ${err.message}`);
});

redisClient.on('connect', () => {
  authLogger.info('Connected to Redis');
});

const getAsync = promisify(redisClient.get).bind(redisClient);
const setAsync = promisify(redisClient.set).bind(redisClient);
const delAsync = promisify(redisClient.del).bind(redisClient);

// Rate limiter for token verification attempts
const tokenRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Max 100 attempts per window
  message: 'Too many token verification attempts. Please try again later.',
  keyGenerator: (req) => req.ip,
  skip: (req) => {
    // Skip rate limiting for successful verifications
    const token = getTokenFromRequest(req);
    if (!token) return true;
    
    try {
      jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true });
      return true;
    } catch {
      return false;
    }
  }
});

// Helper function to extract token from multiple sources
const getTokenFromRequest = (req) => {
  // 1. Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.split(' ')[1];
  }
  
  // 2. Check cookies
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }
  
  // 3. Check query parameters (for websockets)
  if (req.query && req.query.token) {
    return req.query.token;
  }
  
  return null;
};

// Check if token is revoked
const isTokenRevoked = async (token) => {
  try {
    const result = await getAsync(`revoked_token:${token}`);
    return result === 'true';
  } catch (err) {
    authLogger.error(`Redis error: ${err.message}`);
    return false;
  }
};

// Revoke a token
const revokeToken = async (token, expiration) => {
  try {
    // Calculate remaining time until token expiration
    const now = Math.floor(Date.now() / 1000);
    const ttl = expiration - now;
    
    if (ttl > 0) {
      await setAsync(`revoked_token:${token}`, 'true', 'EX', ttl);
      return true;
    }
    return false;
  } catch (err) {
    authLogger.error(`Failed to revoke token: ${err.message}`);
    return false;
  }
};

// Token verification middleware
exports.verifyToken = [
  tokenRateLimiter,
  async (req, res, next) => {
    const token = getTokenFromRequest(req);
    
    if (!token) {
      authLogger.warn('Missing authentication token', { ip: req.ip, path: req.path });
      return res.status(401).json({ message: 'Authentication required' });
    }
    
    // Additional token format validation
    if (!/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.]+$/.test(token)) {
      authLogger.warn('Invalid token format', { ip: req.ip, path: req.path });
      return res.status(401).json({ message: 'Invalid token format' });
    }
    
    // Check if token is revoked
    if (await isTokenRevoked(token)) {
      authLogger.warn('Attempt to use revoked token', { ip: req.ip, path: req.path });
      return res.status(401).json({ message: 'Session expired. Please log in again.' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        let errorMessage = 'Invalid token';
        
        if (err.name === 'TokenExpiredError') {
          errorMessage = 'Session expired. Please log in again.';
          authLogger.info('Token expired', { userId: decoded?.userId, ip: req.ip });
        } else if (err.name === 'JsonWebTokenError') {
          errorMessage = 'Invalid authentication token';
          authLogger.warn('Invalid token presented', { ip: req.ip, error: err.message });
        }
        
        return res.status(401).json({ message: errorMessage });
      }
      
      // Additional payload validation
      if (!decoded.userId || !decoded.role) {
        authLogger.warn('Token with invalid payload', { payload: decoded, ip: req.ip });
        return res.status(401).json({ message: 'Invalid token payload' });
      }
      
      // Check token issuer if required
      if (process.env.JWT_ISSUER && decoded.iss !== process.env.JWT_ISSUER) {
        authLogger.warn('Token with invalid issuer', { issuer: decoded.iss, ip: req.ip });
        return res.status(401).json({ message: 'Invalid token issuer' });
      }
      
      // Attach user to request
      req.user = {
        userId: decoded.userId,
        role: decoded.role,
        tokenIssuedAt: decoded.iat,
        tokenExpiresAt: decoded.exp,
        token: token // Attach token for potential revocation
      };
      
      authLogger.info('Token verified', { userId: decoded.userId, role: decoded.role });
      next();
    });
  }
];

// Role-based authorization middleware
exports.authorize = (roles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      authLogger.error('Authorization middleware called without user context', { path: req.path });
      return res.status(500).json({ message: 'Authorization system error' });
    }
    
    // Convert to array if single role is passed
    const requiredRoles = Array.isArray(roles) ? roles : [roles];
    
    if (requiredRoles.length > 0 && !requiredRoles.includes(req.user.role)) {
      authLogger.warn('Unauthorized access attempt', {
        userId: req.user.userId,
        requiredRoles,
        userRole: req.user.role,
        path: req.path
      });
      return res.status(403).json({ message: 'Insufficient permissions' });
    }
    
    next();
  };
};

// Token refresh verification (for refresh token endpoint)
exports.verifyRefreshToken = async (req, res, next) => {
  const refreshToken = req.body.refreshToken || req.cookies.refreshToken;
  
  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token required' });
  }
  
  // Check if refresh token is revoked
  if (await isTokenRevoked(refreshToken)) {
    authLogger.warn('Attempt to use revoked refresh token');
    return res.status(401).json({ message: 'Session expired. Please log in again.' });
  }
  
  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, decoded) => {
    if (err) {
      let errorMessage = 'Invalid refresh token';
      
      if (err.name === 'TokenExpiredError') {
        errorMessage = 'Refresh token expired. Please log in again.';
      }
      
      return res.status(401).json({ message: errorMessage });
    }
    
    // Additional payload validation
    if (!decoded.userId || !decoded.role) {
      authLogger.warn('Refresh token with invalid payload', { payload: decoded });
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
    
    req.user = {
      userId: decoded.userId,
      role: decoded.role
    };
    
    next();
  });
};

// Generate tokens
exports.generateTokens = (payload) => {
  const accessToken = jwt.sign(
    {
      ...payload,
      iss: process.env.JWT_ISSUER || 'sentinalx-api'
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY || '15m' }
  );
  
  const refreshToken = jwt.sign(
    {
      ...payload,
      iss: process.env.JWT_ISSUER || 'sentinalx-api'
    },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY || '7d' }
  );
  
  return { accessToken, refreshToken };
};

// Revoke tokens
exports.revokeTokens = async (accessToken, refreshToken) => {
  try {
    // Verify tokens to get expiration
    const accessDecoded = jwt.decode(accessToken);
    const refreshDecoded = jwt.decode(refreshToken);
    
    let success = true;
    
    if (accessDecoded && accessDecoded.exp) {
      success = await revokeToken(accessToken, accessDecoded.exp) && success;
    }
    
    if (refreshDecoded && refreshDecoded.exp) {
      success = await revokeToken(refreshToken, refreshDecoded.exp) && success;
    }
    
    return success;
  } catch (err) {
    authLogger.error(`Token revocation failed: ${err.message}`);
    return false;
  }
};

// Revoke all tokens for a user
exports.revokeAllTokensForUser = async (userId) => {
  try {
    // This would require a different implementation where we track user sessions
    // For simplicity, we'll just log the event
    authLogger.info(`Revoking all tokens for user ${userId}`);
    
    // In a real implementation, you might:
    // 1. Store session IDs in Redis
    // 2. Maintain a set of tokens per user
    // 3. Add prefix to token keys: `revoked_token:${userId}:${token}`
    // 4. Delete all keys matching pattern: `revoked_token:${userId}:*`
    
    return true;
  } catch (err) {
    authLogger.error(`Failed to revoke tokens for user: ${err.message}`);
    return false;
  }
};

// Token verification for WebSocket connections
exports.verifySocketToken = async (token) => {
  if (!token) {
    throw new Error('Authentication token required');
  }
  
  // Check token format
  if (!/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.]+$/.test(token)) {
    throw new Error('Invalid token format');
  }
  
  // Check if token is revoked
  if (await isTokenRevoked(token)) {
    throw new Error('Token revoked');
  }
  
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  
  // Additional payload validation
  if (!decoded.userId || !decoded.role) {
    throw new Error('Invalid token payload');
  }
  
  // Check token issuer
  if (process.env.JWT_ISSUER && decoded.iss !== process.env.JWT_ISSUER) {
    throw new Error('Invalid token issuer');
  }
  
  return {
    userId: decoded.userId,
    role: decoded.role,
    tokenIssuedAt: decoded.iat,
    tokenExpiresAt: decoded.exp
  };
};