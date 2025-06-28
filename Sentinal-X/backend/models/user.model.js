const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters'],
        maxlength: [30, 'Username cannot exceed 30 characters'],
        match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email address']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        select: false,
        minlength: [8, 'Password must be at least 8 characters'],
        validate: {
            validator: function(v) {
                return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
            },
            message: 'Password must contain at least: 1 uppercase, 1 lowercase, 1 number, and 1 special character'
        }
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'moderator'],
        default: 'user'
    },
    lastLogin: {
        type: Date
    },
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: {
        type: String,
        select: false
    },
    verificationExpires: {
        type: Date,
        select: false
    },
    passwordResetToken: {
        type: String,
        select: false
    },
    passwordResetExpires: {
        type: Date,
        select: false
    },
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    twoFactorSecret: {
        type: String,
        select: false
    },
    profile: {
        firstName: {
            type: String,
            trim: true,
            maxlength: [50, 'First name cannot exceed 50 characters']
        },
        lastName: {
            type: String,
            trim: true,
            maxlength: [50, 'Last name cannot exceed 50 characters']
        },
        avatar: {
            type: String,
            default: 'default-avatar.jpg'
        }
    },
    status: {
        type: String,
        enum: ['active', 'suspended', 'deactivated'],
        default: 'active'
    }
}, {
    timestamps: true,
    toJSON: {
        virtuals: true,
        transform: function(doc, ret) {
            // Remove sensitive fields when converting to JSON
            delete ret.password;
            delete ret.loginAttempts;
            delete ret.lockUntil;
            delete ret.verificationToken;
            delete ret.verificationExpires;
            delete ret.passwordResetToken;
            delete ret.passwordResetExpires;
            delete ret.twoFactorSecret;
            delete ret.__v;
            return ret;
        }
    },
    toObject: {
        virtuals: true,
        transform: function(doc, ret) {
            delete ret.password;
            delete ret.loginAttempts;
            delete ret.lockUntil;
            delete ret.verificationToken;
            delete ret.verificationExpires;
            delete ret.passwordResetToken;
            delete ret.passwordResetExpires;
            delete ret.twoFactorSecret;
            delete ret.__v;
            return ret;
        }
    }
});

// Virtual for full name
userSchema.virtual('profile.fullName').get(function() {
    return `${this.profile.firstName || ''} ${this.profile.lastName || ''}`.trim();
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
    return this.lockUntil && this.lockUntil > Date.now();
});

// Pre-save hook to hash password
userSchema.pre('save', async function(next) {
    // Only run this function if password was modified
    if (!this.isModified('password')) return next();
    
    try {
        // Hash password with 12 rounds
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (err) {
        next(err);
    }
});

// Password comparison method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Account lock check
userSchema.methods.incrementLoginAttempts = async function() {
    // If lock has expired, reset attempts
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return await this.updateOne({
            $set: { loginAttempts: 1 },
            $unset: { lockUntil: 1 }
        });
    }
    
    const updates = { $inc: { loginAttempts: 1 } };
    
    // Lock account after 5 failed attempts for 1 hour
    if (this.loginAttempts + 1 >= 5) {
        updates.$set = { 
            lockUntil: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
        };
    }
    
    return await this.updateOne(updates);
};

// Reset login attempts on successful login
userSchema.methods.resetLoginAttempts = async function() {
    return await this.updateOne({
        loginAttempts: 0,
        lockUntil: null
    });
};

// Generate password reset token
userSchema.methods.createPasswordResetToken = function() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    this.passwordResetToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');
    
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    return resetToken;
};

// Generate verification token
userSchema.methods.createVerificationToken = function() {
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    this.verificationToken = crypto
        .createHash('sha256')
        .update(verificationToken)
        .digest('hex');
    
    this.verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    
    return verificationToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;