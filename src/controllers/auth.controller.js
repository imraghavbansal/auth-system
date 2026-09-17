import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";
import { sendEmail } from "../services/email.service.js";
import {generateOtp, getOtpHtml} from "../utils/utils.js";
import otpModel from "../models/otp.model.js";


export async function register(req, res) {
    const { username, email, password } = req.body;
     const isUserExist = await userModel.findOne({ 
        $or: [
            { username },
            { email }
        ]
      });

    if (isUserExist) {
        return res.status(409).json({ message: "Username or Email already exists" });
    }

    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

    const user = await userModel.create({ username, email, password: hashedPassword });

    const otp = generateOtp();
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    const otpData = await otpModel.create({ email, user: user._id, otpHash });
    const otpHtml = getOtpHtml(otp);
    await sendEmail(email, "OTP Verification", "", otpHtml);
     

    res.status(201).json({ message: "User registered successfully", 
        user:{
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    });
    
}

export async function login(req, res) {
    const {email, password} = req.body;
    const user = await userModel.findOne({ email });
    if(!user) {
        return res.status(401).json({ message: "Invalid email or password" });
    }

    if(!user.verified) {
        return res.status(403).json({ message: "Email not verified. Please verify your email before logging in." });
    }

    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");
    if(hashedPassword !== user.password) {
        return res.status(401).json({ message: "Invalid email or password" });
    }
    const refreshToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "7d" });
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const session = await sessionModel.create({
        userId: user._id,
        refreshTokenHash,
        ip: req.ip,
        userAgent: req.headers['user-agent']
    })
    const accessToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "15m" });
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })
    res.status(200).json({ message: "User logged in successfully", 
        user:{
            username: user.username,
            email: user.email,
        },
        accessToken
    })
}

export async function getMe(req, res) {
    const token = req.headers.authorization?.split(" ")[1];
    if(!token) {
        return res.status(401).json({ message: "No token provided" });
    }
    const decoded = jwt.verify(token, config.JWT_SECRET)
    const user = await userModel.findById(decoded.id);
    res.status(200).json({
        message: "User fetched successfully",
        user: {
            username: user.username,
            email: user.email,
        }
    })
}

export async function refreshToken(req, res) {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) {
        return res.status(401).json({ message: "No refresh token provided" });
    }
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const session = await sessionModel.findOne({ 
        refreshTokenHash,
        revoked: false
    })
    if(!session) {
        return res.status(401).json({ message: "Invalid refresh token" });
    }


    const user = await userModel.findById(decoded.id);
    const accessToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "15m" });

    const newRefreshToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "7d" });

    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");
    session.refreshTokenHash = newRefreshTokenHash;
    await session.save();


    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })

    res.status(200).json({ message: "Access token refreshed successfully", accessToken });
}

export async function logout(req, res) {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) {
        return res.status(401).json({ message: "No refresh token provided" });
    }
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const session = await sessionModel.findOne({ 
        refreshTokenHash,
        revoked: false
    })
     if(!session) {
        return res.status(401).json({ message: "Invalid refresh token" });
    } 
    session.revoked = true;
    await session.save();
    res.clearCookie("refreshToken");
    res.status(200).json({ message: "User logged out successfully" });
}

export async function logoutAllSessions(req, res) {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) {
        return res.status(401).json({ message: "No refresh token provided" });
    }
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
    await sessionModel.updateMany({ userId: decoded.id ,revoked:false}, { revoked: true });
    res.clearCookie("refreshToken");
    res.status(200).json({ message: "User logged out from all sessions successfully" });
}

export async function verifyEmail(req, res) {
    const {otp, email} = req.body;
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    const otpDoc = await otpModel.findOne({ email, otpHash });
    if(!otpDoc) {
        return res.status(400).json({ message: "Invalid OTP" });
    }
    const user = await userModel.findByIdAndUpdate(otpDoc.user, { verified: true }, { new: true });

    await otpModel.deleteMany({ user: user._id });
    res.status(200).json({ message: "Email verified successfully", user: {
        username: user.username,
        email: user.email,
        verified: user.verified
    }});
}

export async function forgotPassword(req, res) {
    const { email } = req.body;

    const user = await userModel.findOne({ email });

    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");

    const resetTokenHash = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    user.resetPasswordToken = resetTokenHash;
    user.resetPasswordTokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await user.save();

    const resetUrl = `http://localhost:3000/api/auth/reset-password?token=${resetToken}&email=${email}`;

    await sendEmail(
        email,
        "Password Reset",
        `Reset your password using this link: ${resetUrl}`,
        `<p>Reset your password using this link:</p><a href="${resetUrl}">${resetUrl}</a>`
    );

    res.status(200).json({
        message: "Password reset link sent successfully"
    });
}

export async function resetPassword(req, res) {
    const { token, email, password } = req.body;

    if (!token || !email || !password) {
        return res.status(400).json({
            message: "Token, email and password are required"
        });
    }

    const user = await userModel.findOne({ email });

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const resetTokenHash = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

    if (
        !user.resetPasswordToken ||
        user.resetPasswordToken !== resetTokenHash
    ) {
        return res.status(400).json({
            message: "Invalid reset token"
        });
    }

    if (
        !user.resetPasswordTokenExpiresAt ||
        user.resetPasswordTokenExpiresAt.getTime() < Date.now()
    ) {
        return res.status(400).json({
            message: "Reset token has expired"
        });
    }

    const hashedPassword = crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");

    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordTokenExpiresAt = null;

    await user.save();

    await sessionModel.updateMany(
        { userId: user._id, revoked: false },
        { revoked: true }
    );

    res.status(200).json({
        message: "Password reset successfully"
    });
}