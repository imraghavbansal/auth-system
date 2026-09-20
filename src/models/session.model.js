import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: [true, "User ID is required"]
    },

    refreshTokenHash: {
        type: String,
        required: [true, "Refresh token is required"]
    },

    ip: {
        type: String,
        required: [true, "IP address is required"]
    },

    userAgent: {
        type: String,
        required: [true, "User agent is required"]
    },

    revoked: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

sessionSchema.index({
    userId: 1,
    revoked: 1
});

sessionSchema.index({
    refreshTokenHash: 1,
    revoked: 1
});

const sessionModel = mongoose.model("Sessions", sessionSchema);

export default sessionModel;