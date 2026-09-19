import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";
import { sendEmail } from "../services/email.service.js";
import {generateOtp, getOtpHtml} from "../utils/utils.js";
import otpModel from "../models/otp.model.js";
import argon2 from "argon2";


export async function register(req, res) {
    const { username, email, password } = req.body;

    const isUserExist = await userModel.findOne({
        $or: [
            { username },
            { email }
        ]
    });

    if (isUserExist) {
        return res.status(409).json({
            message: "Username or Email already exists"
        });
    }

    const hashedPassword = await argon2.hash(password, {
        type: argon2.argon2id
    });

    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    });

    const otp = generateOtp();

    const otpHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await otpModel.create({
        email,
        user: user._id,
        otpHash,
        purpose: "EMAIL_VERIFICATION",
        expiresAt
    });

    const otpHtml = getOtpHtml(otp);

    await sendEmail(
        email,
        "OTP Verification",
        "",
        otpHtml
    );

    res.status(201).json({
        message: "User registered successfully",
        user: {
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    });
}

export async function login(req, res) {
    const { email, password } = req.body;

    const user = await userModel.findOne({ email });

    if (!user) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    if (!user.verified) {
        return res.status(403).json({
            message: "Email not verified. Please verify your email before logging in."
        });
    }

    const isPasswordValid = await argon2.verify(
        user.password,
        password
    );

    if (!isPasswordValid) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    const refreshToken = jwt.sign(
        { id: user._id },
        config.JWT_SECRET,
        { expiresIn: "7d" }
    );

    const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

    const session = await sessionModel.create({
        userId: user._id,
        refreshTokenHash,
        ip: req.ip,
        userAgent: req.headers["user-agent"]
    });

    const accessToken = jwt.sign(
        { id: user._id },
        config.JWT_SECRET,
        { expiresIn: "15m" }
    );

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(200).json({
        message: "User logged in successfully",
        user: {
            username: user.username,
            email: user.email
        },
        accessToken
    });
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
    const { otp, email } = req.body;

    if (!otp || !email) {
        return res.status(400).json({
            message: "OTP and email are required"
        });
    }

    const otpHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const otpDoc = await otpModel.findOne({
        email,
        otpHash,
        purpose: "EMAIL_VERIFICATION"
    });

    if (!otpDoc) {
        return res.status(400).json({
            message: "Invalid OTP"
        });
    }

    if (otpDoc.expiresAt < new Date()) {
        await otpModel.findByIdAndDelete(otpDoc._id);

        return res.status(400).json({
            message: "OTP has expired"
        });
    }

    const user = await userModel.findByIdAndUpdate(
        otpDoc.user,
        { verified: true },
        { new: true }
    );

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    await otpModel.deleteMany({
        user: user._id,
        purpose: "EMAIL_VERIFICATION"
    });

    res.status(200).json({
        message: "Email verified successfully",
        user: {
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    });
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

    const hashedPassword = await argon2.hash(password, {
    type: argon2.argon2id
     });

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

export async function changePassword(req, res) {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({
            message: "Current password and new password are required"
        });
    }

    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "No token provided"
        });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const isCurrentPasswordValid = await argon2.verify(
    user.password,
    currentPassword
);

if (!isCurrentPasswordValid) {
    return res.status(401).json({
        message: "Current password is incorrect"
    });
}
    
    const newPasswordHash = await argon2.hash(newPassword, {
        type: argon2.argon2id
    });

    user.password = newPasswordHash;

    await user.save();

    await sessionModel.updateMany(
        { userId: user._id, revoked: false },
        { revoked: true }
    );

    res.status(200).json({
        message: "Password changed successfully"
    });
}

export async function resendOtp(req, res) {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            message: "Email is required"
        });
    }

    const user = await userModel.findOne({ email });

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    if (user.verified) {
        return res.status(400).json({
            message: "Email is already verified"
        });
    }

    // Check whether the user recently requested an OTP
    const existingOtp = await otpModel.findOne({
        email,
        user: user._id,
        purpose: "EMAIL_VERIFICATION"
    });

    if (existingOtp) {
        const cooldown = 60 * 1000;
        const timeSinceCreated = Date.now() - existingOtp.createdAt.getTime();

        if (timeSinceCreated < cooldown) {
            const remainingSeconds = Math.ceil(
                (cooldown - timeSinceCreated) / 1000
            );

            return res.status(429).json({
                message: `Please wait ${remainingSeconds} seconds before requesting another OTP`
            });
        }
    }

    await otpModel.deleteMany({
        email,
        user: user._id,
        purpose: "EMAIL_VERIFICATION"
    });

    const otp = generateOtp();

    const otpHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await otpModel.create({
        email,
        user: user._id,
        otpHash,
        purpose: "EMAIL_VERIFICATION",
        expiresAt
    });

    const otpUrl = `http://localhost:3000/api/auth/verify-otp?email=${email}&otp=${otp}`;

    await sendEmail(
        email,
        "OTP Verification",
        `Your OTP is: ${otp}. Use this OTP to verify your email.`,
        `
            <p>Your email verification OTP is:</p>
            <h2>${otp}</h2>
            <p>This OTP expires in 10 minutes.</p>
            <p>Enter this OTP in the verification request to verify your email.</p>
            <p>Or use this verification link:</p>
            <a href="${otpUrl}">${otpUrl}</a>
        `
    );

    res.status(200).json({
        message: "OTP sent successfully"
    });
}

export async function deleteAccount(req, res) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "No token provided"
        });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    await sessionModel.deleteMany({
        userId: user._id
    });

    await otpModel.deleteMany({
        user: user._id
    });

    await userModel.findByIdAndDelete(user._id);

    res.status(200).json({
        message: "Account deleted successfully"
    });
}

export async function getProfile(req, res) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "No token provided"
        });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    res.status(200).json({
        message: "User profile fetched successfully",
        user: {
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    });
}

export async function updateProfile(req, res) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "No token provided"
        });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const { username } = req.body;

    if (username !== undefined) {
        user.username = username;
    }

    await user.save();

    res.status(200).json({
        message: "User profile updated successfully",
        user: {
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    });
}

export async function changeEmail(req, res) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "No token provided"
        });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            message: "New email is required"
        });
    }

    if (email === user.email) {
        return res.status(400).json({
            message: "New email must be different from current email"
        });
    }

    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
        return res.status(409).json({
            message: "Email is already in use"
        });
    }

    await otpModel.deleteMany({
        user: user._id,
        purpose: "EMAIL_CHANGE"
    });

    const otp = generateOtp();

    const otpHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await otpModel.create({
        email,
        user: user._id,
        otpHash,
        purpose: "EMAIL_CHANGE",
        expiresAt
    });

    await sendEmail(
        email,
        "Email Change Verification",
        `Your OTP is: ${otp}. Use this OTP to verify your new email address.`,
        `
            <p>Your email change verification OTP is:</p>
            <h2>${otp}</h2>
            <p>This OTP expires in 10 minutes.</p>
            <p>Enter this OTP to verify your new email address.</p>
        `
    );

    res.status(200).json({
        message: "OTP sent to new email address"
    });
}

export async function verifyEmailChange(req, res) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "No token provided"
        });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const { otp, email } = req.body;

    if (!otp || !email) {
        return res.status(400).json({
            message: "OTP and new email are required"
        });
    }

    const otpHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const otpDoc = await otpModel.findOne({
        user: user._id,
        email,
        otpHash,
        purpose: "EMAIL_CHANGE"
    });

    if (!otpDoc) {
        return res.status(400).json({
            message: "Invalid OTP"
        });
    }

    if (otpDoc.expiresAt < new Date()) {
        await otpModel.findByIdAndDelete(otpDoc._id);

        return res.status(400).json({
            message: "OTP has expired"
        });
    }

    const existingUser = await userModel.findOne({
        email,
        _id: { $ne: user._id }
    });

    if (existingUser) {
        return res.status(409).json({
            message: "Email is already in use"
        });
    }

    user.email = email;
    user.verified = true;

    await user.save();

    await sessionModel.deleteMany({
        userId: user._id
    });

    await otpModel.findByIdAndDelete(otpDoc._id);

    res.status(200).json({
        message: "Email changed successfully",
        user: {
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    });
}

export async function getSessions(req, res) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "No token provided"
        });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const sessions = await sessionModel.find({
        userId: user._id,
        revoked: false
    }).select("_id ip userAgent createdAt updatedAt");

    res.status(200).json({
        message: "Sessions fetched successfully",
        sessions
    });
}

export async function revokeSession(req, res) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "No token provided"
        });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const { sessionId } = req.params;

    if (!sessionId) {
        return res.status(400).json({
            message: "Session ID is required"
        });
    }

    const session = await sessionModel.findOne({
        _id: sessionId,
        userId: user._id,
        revoked: false
    });

    if (!session) {
        return res.status(404).json({
            message: "Session not found"
        });
    }

    session.revoked = true;

    await session.save();

    res.status(200).json({
        message: "Session revoked successfully"
    });
}