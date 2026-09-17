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
    }
}, { timestamps: true }); 

const otpModel = mongoose.model("OTP", otpSchema); 
export default otpModel;