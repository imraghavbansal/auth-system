import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Username is required"],
        unique: [true, "Username must be unique"]
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: [true, "Email must be unique"]
    
    },
    password: {
        type: String,
        required: [true, "Password is required"]
    },
    verified: {
        type: Boolean,
        default: false
    },
    resetPasswordToken: {
    type: String,
    default: null
    },
    resetPasswordTokenExpiresAt: {
    type: Date,
    default: null
}
})

const userModel = mongoose.model("Users", userSchema);

export default userModel;