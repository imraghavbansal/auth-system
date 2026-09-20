import mongoose from "mongoose";

const loginAttemptSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, "Email is required"],
        lowercase: true,
        trim: true
    },

    ip: {
        type: String,
        required: [true, "IP address is required"]
    },

    attempts: {
        type: Number,
        default: 0
    },

    windowStartedAt: {
        type: Date,
        required: true
    },

    blockedUntil: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

loginAttemptSchema.index({
    email: 1,
    ip: 1
});

const loginAttemptModel = mongoose.model(
    "LoginAttempts",
    loginAttemptSchema
);

export default loginAttemptModel;