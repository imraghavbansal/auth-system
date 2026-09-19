import mongoose from "mongoose";

const otpSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, "Email is required"]
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Users",
        required: [true, "User reference is required"]
    },
    otpHash: {
        type: String,
        required: [true, "OTP hash is required"]
    },
    purpose: {
    type: String,
    required: true,
    enum: ["EMAIL_VERIFICATION", "EMAIL_CHANGE"]
    },

    expiresAt: {
    type: Date,
    required: true,
    index: true,
    expires: 0
    }
}, { timestamps: true }); 

const otpModel = mongoose.model("OTP", otpSchema); 
export default otpModel;