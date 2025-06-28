const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    sender: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User',
        required: [true, 'Sender ID is required'],
        index: true
    },
    receiver: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User',
        required: [true, 'Receiver ID is required'],
        index: true
    },
    text: {
        type: {
            cipher: { 
                type: String, 
                required: function() { return this.type === 'text'; } 
            },
            nonce: { 
                type: String, 
                required: function() { return this.type === 'text'; } 
            },
            senderPublicKey: { 
                type: String, 
                required: function() { return this.type === 'text'; } 
            }
        },
        required: false
    },
    file: {
        type: {
            cipher: { 
                type: String, 
                required: function() { return this.type !== 'text'; } 
            },
            nonce: { 
                type: String, 
                required: function() { return this.type !== 'text'; } 
            },
            senderPublicKey: { 
                type: String, 
                required: function() { return this.type !== 'text'; } 
            }
        },
        required: false
    },
    status: { 
        type: String, 
        enum: ['sent', 'delivered', 'read'], 
        default: 'sent'
    },
    readAt: {
        type: Date
    },
    deletions: [{
        userId: { 
            type: mongoose.Schema.Types.ObjectId, 
            ref: 'User',
            required: true
        },
        deletedAt: {
            type: Date,
            default: Date.now
        },
        _id: false
    }],
    edits: [{
        text: {
            cipher: { type: String },
            nonce: { type: String },
            senderPublicKey: { type: String }
        },
        editedAt: {
            type: Date,
            default: Date.now
        },
        _id: false
    }],
    type: {
        type: String,
        enum: ['text', 'image', 'file', 'video', 'audio'],
        default: 'text'
    },
    reported: {
        type: Boolean,
        default: false,
        validate: {
            validator: function(v) {
                return !v || (v && this.reportReason);
            },
            message: "reportReason required when reported=true"
        }
    },
    reportReason: {
        type: String,
        enum: ['spam', 'harassment', 'inappropriate', 'other']
    }
}, {
    timestamps: true,
    toJSON: {
        virtuals: true,
        transform: function(doc, ret) {
            delete ret.__v;
            delete ret.deletions;
            return ret;
        }
    },
    toObject: {
        virtuals: true,
        transform: function(doc, ret) {
            delete ret.__v;
            return ret;
        }
    }
});

// Add compound indexes
messageSchema.index({ status: 1, receiver: 1 });
messageSchema.index({ 'deletions.userId': 1 });
messageSchema.index({ createdAt: 1 });

// Prevent sender == receiver
messageSchema.pre('save', function(next) {
    if (this.sender.equals(this.receiver)) {
        const err = new Error("Sender and receiver cannot be identical");
        next(err);
    } else {
        next();
    }
});

// Validate content based on message type
messageSchema.pre('validate', function(next) {
    if (this.type === 'text') {
        if (!this.text || !this.text.cipher || !this.text.nonce || !this.text.senderPublicKey) {
            next(new Error('Text content required for text messages'));
        }
    } else {
        if (!this.file || !this.file.cipher || !this.file.nonce || !this.file.senderPublicKey) {
            next(new Error('File content required for non-text messages'));
        }
    }
    next();
});

// Static method to mark message as read
messageSchema.statics.markAsRead = async function(messageId, userId) {
    const message = await this.findById(messageId);
    
    if (!message) return null;
    if (message.status === 'read') return message;
    if (!message.receiver.equals(userId)) return null;
    
    message.status = 'read';
    message.readAt = new Date();
    return message.save();
};

// Static method for soft deletion
messageSchema.statics.softDelete = async function(messageId, userId) {
    return this.findOneAndUpdate(
        {
            _id: messageId,
            $or: [{ sender: userId }, { receiver: userId }],
            'deletions.userId': { $ne: userId }
        },
        {
            $push: { 
                deletions: { 
                    userId: userId,
                    deletedAt: new Date()
                } 
            }
        },
        { new: true }
    );
};

// Check message visibility
messageSchema.methods.isVisibleTo = function(userId) {
    const userDeleted = this.deletions.some(d => d.userId.equals(userId));
    const isParticipant = this.sender.equals(userId) || this.receiver.equals(userId);
    const hideReported = this.reported && !this.sender.equals(userId);
    
    return !userDeleted && isParticipant && !hideReported;
};

// Edit encrypted text (with validation)
messageSchema.methods.editMessage = async function(newText, userId) {
    if (!this.sender.equals(userId)) {
        throw new Error('Only sender can edit message');
    }
    if (this.type !== 'text') {
        throw new Error('Only text messages editable');
    }
    if (!newText.cipher || !newText.nonce || !newText.senderPublicKey) {
        throw new Error('Invalid message format');
    }

    // Preserve edit history (limit to last 10 edits)
    if (this.edits.length >= 10) this.edits.shift();
    
    this.edits.push({
        text: this.text,
        editedAt: new Date()
    });

    this.text = newText;
    return this.save();
};

module.exports = mongoose.model('Message', messageSchema);