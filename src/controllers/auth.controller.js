import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";
import emailQueue from "../queues/email.queue.js";
import { generateOtp, getOtpHtml } from "../utils/utils.js";
import otpModel from "../models/otp.model.js";
import argon2 from "argon2";
import loginAttemptModel from "../models/login-attempt.model.js";
import {
    generateGoogleState,
    getGoogleAuthorizationUrl,
    getGoogleUser
} from "../services/google-auth.service.js";

const refreshCookieOptions = {
    httpOnly: true,
    secure: config.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000
};

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

    const otpDoc = await otpModel.create({
        email,
        user: user._id,
        otpHash,
        purpose: "EMAIL_VERIFICATION",
        expiresAt
    });

    const otpHtml = getOtpHtml(otp);

    try {
        await emailQueue.add("send-email", {
            to: email,
            subject: "OTP Verification",
            text: "",
            html: otpHtml
        });
    } catch (error) {
        await otpModel.findByIdAndDelete(otpDoc._id);
        await userModel.findByIdAndDelete(user._id);

        throw error;
    }

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

    const normalizedEmail = email.trim().toLowerCase();
    const ip = req.ip;

    let loginAttempt = await loginAttemptModel.findOne({
        email: normalizedEmail,
        ip
    });

    const now = Date.now();
    const windowDuration = 15 * 60 * 1000;
    const maxAttempts = 5;

    if (
        loginAttempt &&
        now - loginAttempt.windowStartedAt.getTime() >= windowDuration
    ) {
        loginAttempt.attempts = 0;
        loginAttempt.windowStartedAt = new Date();
        loginAttempt.blockedUntil = null;

        await loginAttempt.save();
    }

    if (
        loginAttempt?.blockedUntil &&
        loginAttempt.blockedUntil.getTime() > now
    ) {
        const remainingSeconds = Math.ceil(
            (loginAttempt.blockedUntil.getTime() - now) / 1000
        );

        return res.status(429).json({
            message: `Too many failed login attempts. Please try again in ${remainingSeconds} seconds`
        });
    }

    const user = await userModel.findOne({
        email: normalizedEmail
    });

    if (!user) {
        if (!loginAttempt) {
            loginAttempt = await loginAttemptModel.create({
                email: normalizedEmail,
                ip,
                attempts: 1,
                windowStartedAt: new Date()
            });
        } else {
            loginAttempt.attempts += 1;

            if (loginAttempt.attempts >= maxAttempts) {
                loginAttempt.blockedUntil = new Date(
                    now + windowDuration
                );
            }

            await loginAttempt.save();
        }

        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    if (user.authProvider === "google") {
    return res.status(401).json({
        message: "This account uses Google login. Please continue with Google."
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
        if (!loginAttempt) {
            loginAttempt = await loginAttemptModel.create({
                email: normalizedEmail,
                ip,
                attempts: 1,
                windowStartedAt: new Date()
            });
        } else {
            loginAttempt.attempts += 1;

            if (loginAttempt.attempts >= maxAttempts) {
                loginAttempt.blockedUntil = new Date(
                    now + windowDuration
                );
            }

            await loginAttempt.save();
        }

        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    if (loginAttempt) {
        await loginAttemptModel.deleteOne({
            _id: loginAttempt._id
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

    await sessionModel.create({
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

    res.cookie("refreshToken", refreshToken, refreshCookieOptions);

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
    const user = req.user;

    res.status(200).json({
        message: "User fetched successfully",
        user: {
            username: user.username,
            email: user.email
        }
    });
}

export async function googleAuth(req, res) {
    const state = generateGoogleState();

    res.cookie("googleOAuthState", state, {
        httpOnly: true,
        secure: config.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 10 * 60 * 1000
    });

    const authorizationUrl = getGoogleAuthorizationUrl(state);

    res.redirect(authorizationUrl);
}

export async function googleCallback(req, res) {
    const { code, state } = req.query;

    const storedState = req.cookies.googleOAuthState;

    res.clearCookie("googleOAuthState", {
        httpOnly: true,
        secure: config.NODE_ENV === "production",
        sameSite: "lax"
    });

    if (!state || !storedState || state !== storedState) {
        return res.status(400).json({
            message: "Invalid OAuth state"
        });
    }

    if (!code) {
        return res.status(400).json({
            message: "Google authorization code is missing"
        });
    }

    let googleUser;

    try {
        googleUser = await getGoogleUser(code);
    } catch (error) {
        console.error("Google OAuth error:", error);

        return res.status(401).json({
            message: "Unable to authenticate with Google"
        });
    }

    if (
        !googleUser.googleId ||
        !googleUser.email
    ) {
        return res.status(401).json({
            message: "Google account information is incomplete"
        });
    }

    if (!googleUser.emailVerified) {
        return res.status(403).json({
            message: "Google email is not verified"
        });
    }

    let user = await userModel.findOne({
        googleId: googleUser.googleId
    });

    if (!user) {
        const existingUser = await userModel.findOne({
            email: googleUser.email
        });

        if (existingUser) {
            return res.status(409).json({
                message:
                    "An account with this email already exists. Please log in with your existing account."
            });
        }

        let usernameBase = googleUser.email
            .split("@")[0]
            .replace(/[^a-zA-Z0-9_]/g, "_");

        if (usernameBase.length < 3) {
            usernameBase = `user_${usernameBase}`;
        }

        let username = usernameBase;
        let suffix = 1;

        while (await userModel.exists({ username })) {
            username = `${usernameBase}_${suffix}`;
            suffix += 1;
        }

        user = await userModel.create({
            username,
            email: googleUser.email,
            authProvider: "google",
            googleId: googleUser.googleId,
            verified: true
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

    await sessionModel.create({
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

    res.cookie(
        "refreshToken",
        refreshToken,
        refreshCookieOptions
    );

    res.status(200).json({
        message: "Google login successful",
        user: {
            username: user.username,
            email: user.email
        },
        accessToken
    });
}

export async function refreshToken(req, res) {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({
            message: "No refresh token provided"
        });
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false
    });

    if (!session) {
        return res.status(401).json({
            message: "Invalid refresh token"
        });
    }

    const user = await userModel.findById(decoded.id);

    const accessToken = jwt.sign(
        { id: user._id },
        config.JWT_SECRET,
        { expiresIn: "15m" }
    );

    const newRefreshToken = jwt.sign(
        { id: user._id },
        config.JWT_SECRET,
        { expiresIn: "7d" }
    );

    const newRefreshTokenHash = crypto
        .createHash("sha256")
        .update(newRefreshToken)
        .digest("hex");

    session.refreshTokenHash = newRefreshTokenHash;

    await session.save();

    res.cookie("refreshToken", newRefreshToken, refreshCookieOptions);

    res.status(200).json({
        message: "Access token refreshed successfully",
        accessToken
    });
}

export async function logout(req, res) {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({
            message: "No refresh token provided"
        });
    }

    const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false
    });

    if (!session) {
        return res.status(401).json({
            message: "Invalid refresh token"
        });
    }

    session.revoked = true;

    await session.save();

    res.clearCookie("refreshToken", refreshCookieOptions);

    res.status(200).json({
        message: "User logged out successfully"
    });
}

export async function logoutAllSessions(req, res) {
    await sessionModel.updateMany(
        {
            userId: req.user._id,
            revoked: false
        },
        {
            revoked: true
        }
    );

    res.clearCookie("refreshToken", refreshCookieOptions);

    res.status(200).json({
        message: "User logged out from all sessions successfully"
    });
}

export async function verifyEmail(req, res) {
    const { otp, email } = req.body;

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
        return res.status(404).json({
            message: "User not found"
        });
    }

    if (user.authProvider === "google") {
    return res.status(400).json({
        message: "Google accounts cannot reset their password here. Please continue with Google."
    });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");

    const resetTokenHash = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    user.resetPasswordToken = resetTokenHash;
    user.resetPasswordTokenExpiresAt = new Date(
        Date.now() + 15 * 60 * 1000
    );

    await user.save();

    const resetUrl = `${config.APP_BASE_URL}/api/auth/reset-password?token=${resetToken}&email=${email}`;

    try {
        await emailQueue.add("send-email", {
            to: email,
            subject: "Password Reset",
            text: `Reset your password using this link: ${resetUrl}`,
            html: `<p>Reset your password using this link:</p><a href="${resetUrl}">${resetUrl}</a>`
        });
    } catch (error) {
        user.resetPasswordToken = null;
        user.resetPasswordTokenExpiresAt = null;

        await user.save();

        throw error;
    }

    res.status(200).json({
        message: "Password reset link sent successfully"
    });
}

export async function resetPassword(req, res) {
    const { token, email, password } = req.body;

    const user = await userModel.findOne({ email });

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    if (user.authProvider === "google") {
    return res.status(400).json({
        message: "Google accounts cannot reset their password here. Please continue with Google."
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
        {
            userId: user._id,
            revoked: false
        },
        {
            revoked: true
        }
    );

    res.status(200).json({
        message: "Password reset successfully"
    });
}

export async function changePassword(req, res) {
    const { currentPassword, newPassword } = req.body;
    const user = req.user;

    if (user.authProvider === "google") {
        return res.status(400).json({
            message: "Google accounts cannot change password here. Please continue with Google."
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
        {
            userId: user._id,
            revoked: false
        },
        {
            revoked: true
        }
    );

    res.status(200).json({
        message: "Password changed successfully"
    });
}

export async function resendOtp(req, res) {
    const { email } = req.body;

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

    const existingOtp = await otpModel.findOne({
        email,
        user: user._id,
        purpose: "EMAIL_VERIFICATION"
    });

    if (existingOtp) {
        const cooldown = 60 * 1000;
        const timeSinceCreated =
            Date.now() - existingOtp.createdAt.getTime();

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

    const otpDoc = await otpModel.create({
        email,
        user: user._id,
        otpHash,
        purpose: "EMAIL_VERIFICATION",
        expiresAt
    });

    const otpUrl = `${config.APP_BASE_URL}/api/auth/verify-otp?email=${email}&otp=${otp}`;

    try {
        await emailQueue.add("send-email", {
            to: email,
            subject: "OTP Verification",
            text: `Your OTP is: ${otp}. Use this OTP to verify your email.`,
            html: `
                <p>Your email verification OTP is:</p>
                <h2>${otp}</h2>
                <p>This OTP expires in 10 minutes.</p>
                <p>Enter this OTP in the verification request to verify your email.</p>
                <p>Or use this verification link:</p>
                <a href="${otpUrl}">${otpUrl}</a>
            `
        });
    } catch (error) {
        await otpModel.findByIdAndDelete(otpDoc._id);

        throw error;
    }

    res.status(200).json({
        message: "OTP sent successfully"
    });
}

export async function deleteAccount(req, res) {
    const user = req.user;

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
    const user = req.user;

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
    const user = req.user;
    const { username } = req.body;

    user.username = username;

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
    const user = req.user;
    const { email } = req.body;

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

    const otpDoc = await otpModel.create({
        email,
        user: user._id,
        otpHash,
        purpose: "EMAIL_CHANGE",
        expiresAt
    });

    try {
        await emailQueue.add("send-email", {
            to: email,
            subject: "Email Change Verification",
            text: `Your OTP is: ${otp}. Use this OTP to verify your new email address.`,
            html: `
                <p>Your email change verification OTP is:</p>
                <h2>${otp}</h2>
                <p>This OTP expires in 10 minutes.</p>
                <p>Enter this OTP to verify your new email address.</p>
            `
        });
    } catch (error) {
        await otpModel.findByIdAndDelete(otpDoc._id);

        throw error;
    }

    res.status(200).json({
        message: "OTP sent to new email address"
    });
}

export async function verifyEmailChange(req, res) {
    const user = req.user;
    const { otp, email } = req.body;

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
    const user = req.user;

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
    const user = req.user;
    const { sessionId } = req.params;

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