import {
    beforeAll,
    afterAll,
    afterEach,
    describe,
    expect,
    it,
    vi
} from "vitest";

import mongoose from "mongoose";
import argon2 from "argon2";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import request from "supertest";

vi.mock("../config/redis.js", () => ({
    default: {
        status: "ready",
        ping: vi.fn().mockResolvedValue("PONG")
    }
}));

vi.mock("../queues/email.queue.js", () => ({
    default: {
        add: vi.fn().mockResolvedValue({
            id: "test-email-job"
        })
    }
}));

import app from "../app.js";
import config from "../config/config.js";
import userModel from "../models/user.model.js";
import otpModel from "../models/otp.model.js";
import sessionModel from "../models/session.model.js";
import loginAttemptModel from "../models/login-attempt.model.js";
import emailQueue from "../queues/email.queue.js";

const TEST_PASSWORD = "Password123!";
const TEST_PASSWORD_2 = "NewPassword123!";

const createUser = async ({
    username = `testuser_${Date.now()}_${Math.random()}`,
    email = `test_${Date.now()}_${Math.random()}@example.com`,
    password = TEST_PASSWORD,
    verified = true
} = {}) => {
    const hashedPassword = await argon2.hash(password, {
        type: argon2.argon2id
    });

    return userModel.create({
        username,
        email,
        password: hashedPassword,
        verified
    });
};

const createAccessToken = (userId) => {
    return jwt.sign(
        {
            id: userId
        },
        config.JWT_SECRET,
        {
            expiresIn: "15m"
        }
    );
};

const createRefreshToken = () => {
    return jwt.sign(
        {
            type: "refresh"
        },
        config.JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
};

beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_TEST_URI);
});

afterEach(async () => {
    await Promise.all([
        userModel.deleteMany({}),
        otpModel.deleteMany({}),
        sessionModel.deleteMany({}),
        loginAttemptModel.deleteMany({})
    ]);

    vi.clearAllMocks();

    emailQueue.add.mockResolvedValue({
        id: "test-email-job"
    });
});

afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
});

describe("Authentication security and edge cases", () => {
    describe("Registration", () => {
        it("registers a user successfully and creates an email verification OTP", async () => {
            const email = `register_${Date.now()}@example.com`;

            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    username: `register_${Date.now()}`,
                    email,
                    password: TEST_PASSWORD
                });

            expect(response.status).toBe(201);

            const user = await userModel.findOne({ email });

            expect(user).not.toBeNull();
            expect(user.verified).toBe(false);
            expect(user.password).not.toBe(TEST_PASSWORD);

            const passwordMatches = await argon2.verify(
                user.password,
                TEST_PASSWORD
            );

            expect(passwordMatches).toBe(true);

            const otp = await otpModel.findOne({
                email,
                purpose: "EMAIL_VERIFICATION"
            });

            expect(otp).not.toBeNull();
            expect(otp.expiresAt.getTime()).toBeGreaterThan(Date.now());

            expect(emailQueue.add).toHaveBeenCalled();
        });

        it("rejects duplicate email registration", async () => {
            const email = `duplicate_${Date.now()}@example.com`;

            await createUser({
                email
            });

            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    username: `another_${Date.now()}`,
                    email,
                    password: TEST_PASSWORD
                });

            expect(response.status).toBe(409);
        });

        it("rejects duplicate username registration", async () => {
            const username = `duplicate_username_${Date.now()}`;

            await createUser({
                username
            });

            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    username,
                    email: `another_${Date.now()}@example.com`,
                    password: TEST_PASSWORD
                });

            expect(response.status).toBe(409);
        });

        it("rejects invalid registration input", async () => {
            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    username: "",
                    email: "invalid-email",
                    password: "123"
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe("Validation failed");
            expect(response.body.errors).toBeInstanceOf(Array);
        });

        it("rolls back user and OTP creation when the email queue fails", async () => {
            emailQueue.add.mockRejectedValueOnce(
                new Error("Email queue unavailable")
            );

            const email = `rollback_${Date.now()}@example.com`;

            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    username: `rollback_${Date.now()}`,
                    email,
                    password: TEST_PASSWORD
                });

            expect(response.status).toBe(500);

            const user = await userModel.findOne({ email });
            const otp = await otpModel.findOne({ email });

            expect(user).toBeNull();
            expect(otp).toBeNull();
        });
    });

    describe("Login", () => {
        it("rejects login for a nonexistent user", async () => {
            const response = await request(app)
                .post("/api/auth/login")
                .set("User-Agent", "vitest-integration-test")
                .send({
                    email: `missing_${Date.now()}@example.com`,
                    password: TEST_PASSWORD
                });

            expect(response.status).toBe(401);
        });

        it("rejects login with an incorrect password", async () => {
            const user = await createUser();

            const response = await request(app)
                .post("/api/auth/login")
                .set("User-Agent", "vitest-integration-test")
                .send({
                    email: user.email,
                    password: "WrongPassword123!"
                });

            expect(response.status).toBe(401);
        });

        it("rejects login when the email is not verified", async () => {
            const user = await createUser({
                verified: false
            });

            const response = await request(app)
                .post("/api/auth/login")
                .set("User-Agent", "vitest-integration-test")
                .send({
                    email: user.email,
                    password: TEST_PASSWORD
                });

            expect(response.status).toBe(403);
        });

        it("logs in successfully and creates a session", async () => {
            const user = await createUser();

            const response = await request(app)
                .post("/api/auth/login")
                .set("User-Agent", "vitest-integration-test")
                .send({
                    email: user.email,
                    password: TEST_PASSWORD
                });

            expect(response.status).toBe(200);
            expect(response.headers["set-cookie"]).toBeDefined();

            const session = await sessionModel.findOne({
                userId: user._id
            });

            expect(session).not.toBeNull();
            expect(session.revoked).toBe(false);
            expect(session.refreshTokenHash).toBeDefined();
            expect(session.userAgent).toBe("vitest-integration-test");
        });

        it("rate limits login after five failed attempts", async () => {
            const user = await createUser();

            for (let i = 0; i < 5; i++) {
                const response = await request(app)
                    .post("/api/auth/login")
                    .set("User-Agent", "vitest-integration-test")
                    .send({
                        email: user.email,
                        password: "WrongPassword123!"
                    });

                expect([401, 429]).toContain(response.status);
            }

            const blockedResponse = await request(app)
                .post("/api/auth/login")
                .set("User-Agent", "vitest-integration-test")
                .send({
                    email: user.email,
                    password: TEST_PASSWORD
                });

            expect(blockedResponse.status).toBe(429);
        });
    });

    describe("Email verification OTP", () => {
        it("rejects an invalid OTP", async () => {
            const user = await createUser({
                verified: false
            });

            await otpModel.create({
                email: user.email,
                user: user._id,
                otpHash: crypto
                    .createHash("sha256")
                    .update("123456")
                    .digest("hex"),
                purpose: "EMAIL_VERIFICATION",
                expiresAt: new Date(Date.now() + 10 * 60 * 1000)
            });

            const response = await request(app)
                .get("/api/auth/verify-email")
                .send({
                    email: user.email,
                    otp: "999999"
                });

            expect(response.status).toBe(400);

            const updatedUser = await userModel.findById(user._id);

            expect(updatedUser.verified).toBe(false);
        });

        it("rejects an expired OTP and deletes it", async () => {
            const user = await createUser({
                verified: false
            });

            const otpHash = crypto
                .createHash("sha256")
                .update("123456")
                .digest("hex");

            const otp = await otpModel.create({
                email: user.email,
                user: user._id,
                otpHash,
                purpose: "EMAIL_VERIFICATION",
                expiresAt: new Date(Date.now() - 1000)
            });

            const response = await request(app)
                .get("/api/auth/verify-email")
                .send({
                    email: user.email,
                    otp: "123456"
                });

            expect(response.status).toBe(400);

            const deletedOtp = await otpModel.findById(otp._id);

            expect(deletedOtp).toBeNull();
        });

        it("verifies a valid OTP successfully", async () => {
            const user = await createUser({
                verified: false
            });

            const otpValue = "123456";

            const otpHash = crypto
                .createHash("sha256")
                .update(otpValue)
                .digest("hex");

            await otpModel.create({
                email: user.email,
                user: user._id,
                otpHash,
                purpose: "EMAIL_VERIFICATION",
                expiresAt: new Date(Date.now() + 10 * 60 * 1000)
            });

            const response = await request(app)
                .get("/api/auth/verify-email")
                .send({
                    email: user.email,
                    otp: otpValue
                });

            expect(response.status).toBe(200);

            const updatedUser = await userModel.findById(user._id);

            expect(updatedUser.verified).toBe(true);

            const remainingOtps = await otpModel.find({
                user: user._id,
                purpose: "EMAIL_VERIFICATION"
            });

            expect(remainingOtps).toHaveLength(0);
        });
    });

    describe("Forgot password", () => {
        it("handles forgot password for a nonexistent user", async () => {
            const response = await request(app)
                .post("/api/auth/forgot-password")
                .send({
                    email: `missing_${Date.now()}@example.com`
                });

            expect([200, 404]).toContain(response.status);
        });

        it("creates a password reset token", async () => {
            const user = await createUser();

            const response = await request(app)
                .post("/api/auth/forgot-password")
                .send({
                    email: user.email
                });

            expect(response.status).toBe(200);

            const updatedUser = await userModel.findById(user._id);

            expect(updatedUser.resetPasswordToken).not.toBeNull();
            expect(updatedUser.resetPasswordTokenExpiresAt).not.toBeNull();
            expect(
                updatedUser.resetPasswordTokenExpiresAt.getTime()
            ).toBeGreaterThan(Date.now());

            expect(emailQueue.add).toHaveBeenCalled();
        });

        it("rolls back the reset token when the email queue fails", async () => {
            const user = await createUser();

            emailQueue.add.mockRejectedValueOnce(
                new Error("Email queue unavailable")
            );

            const response = await request(app)
                .post("/api/auth/forgot-password")
                .send({
                    email: user.email
                });

            expect(response.status).toBe(500);

            const updatedUser = await userModel.findById(user._id);

            expect(updatedUser.resetPasswordToken).toBeNull();
            expect(updatedUser.resetPasswordTokenExpiresAt).toBeNull();
        });
    });

    describe("Reset password", () => {
        it("rejects an invalid reset token", async () => {
            const user = await createUser();

            const response = await request(app)
                .post("/api/auth/reset-password")
                .send({
                    email: user.email,
                    token: "invalid-token",
                    password: TEST_PASSWORD_2
                });

            expect(response.status).toBe(400);
        });

        it("rejects an expired reset token", async () => {
            const user = await createUser();

            const rawToken = "valid-token";

            const tokenHash = crypto
                .createHash("sha256")
                .update(rawToken)
                .digest("hex");

            user.resetPasswordToken = tokenHash;
            user.resetPasswordTokenExpiresAt = new Date(Date.now() - 1000);

            await user.save();

            const response = await request(app)
                .post("/api/auth/reset-password")
                .send({
                    email: user.email,
                    token: rawToken,
                    password: TEST_PASSWORD_2
                });

            expect(response.status).toBe(400);
        });

        it("resets the password and revokes all sessions", async () => {
            const user = await createUser();

            const rawToken = "valid-reset-token";

            const tokenHash = crypto
                .createHash("sha256")
                .update(rawToken)
                .digest("hex");

            user.resetPasswordToken = tokenHash;
            user.resetPasswordTokenExpiresAt = new Date(
                Date.now() + 15 * 60 * 1000
            );

            await user.save();

            await sessionModel.create([
                {
                    userId: user._id,
                    refreshTokenHash: crypto
                        .createHash("sha256")
                        .update("refresh-token-1")
                        .digest("hex"),
                    ip: "127.0.0.1",
                    userAgent: "test-agent-1"
                },
                {
                    userId: user._id,
                    refreshTokenHash: crypto
                        .createHash("sha256")
                        .update("refresh-token-2")
                        .digest("hex"),
                    ip: "127.0.0.1",
                    userAgent: "test-agent-2"
                }
            ]);

            const response = await request(app)
                .post("/api/auth/reset-password")
                .send({
                    email: user.email,
                    token: rawToken,
                    password: TEST_PASSWORD_2
                });

            expect(response.status).toBe(200);

            const updatedUser = await userModel.findById(user._id);

            expect(updatedUser.resetPasswordToken).toBeNull();
            expect(updatedUser.resetPasswordTokenExpiresAt).toBeNull();

            const passwordMatches = await argon2.verify(
                updatedUser.password,
                TEST_PASSWORD_2
            );

            expect(passwordMatches).toBe(true);

            const sessions = await sessionModel.find({
                userId: user._id
            });

            expect(sessions).toHaveLength(2);
            expect(sessions.every((session) => session.revoked)).toBe(true);
        });
    });

    describe("Change password", () => {
        it("rejects an incorrect current password", async () => {
            const user = await createUser();

            const accessToken = createAccessToken(user._id.toString());

            const response = await request(app)
                .post("/api/auth/change-password")
                .set("Authorization", `Bearer ${accessToken}`)
                .send({
                    currentPassword: "WrongPassword123!",
                    newPassword: TEST_PASSWORD_2
                });

            expect(response.status).toBe(401);
        });

        it("changes the password and revokes all sessions", async () => {
            const user = await createUser();

            await sessionModel.create([
                {
                    userId: user._id,
                    refreshTokenHash: crypto
                        .createHash("sha256")
                        .update("refresh-token-1")
                        .digest("hex"),
                    ip: "127.0.0.1",
                    userAgent: "test-agent-1"
                },
                {
                    userId: user._id,
                    refreshTokenHash: crypto
                        .createHash("sha256")
                        .update("refresh-token-2")
                        .digest("hex"),
                    ip: "127.0.0.1",
                    userAgent: "test-agent-2"
                }
            ]);

            const accessToken = createAccessToken(user._id.toString());

            const response = await request(app)
                .post("/api/auth/change-password")
                .set("Authorization", `Bearer ${accessToken}`)
                .send({
                    currentPassword: TEST_PASSWORD,
                    newPassword: TEST_PASSWORD_2
                });

            expect(response.status).toBe(200);

            const updatedUser = await userModel.findById(user._id);

            const passwordMatches = await argon2.verify(
                updatedUser.password,
                TEST_PASSWORD_2
            );

            expect(passwordMatches).toBe(true);

            const sessions = await sessionModel.find({
                userId: user._id
            });

            expect(sessions).toHaveLength(2);
            expect(sessions.every((session) => session.revoked)).toBe(true);
        });
    });

    describe("Session revocation", () => {
        it("revokes a specific session belonging to the authenticated user", async () => {
            const user = await createUser();

            const targetSession = await sessionModel.create({
                userId: user._id,
                refreshTokenHash: crypto
                    .createHash("sha256")
                    .update("target-refresh-token")
                    .digest("hex"),
                ip: "127.0.0.1",
                userAgent: "test-agent"
            });

            const accessToken = createAccessToken(user._id.toString());

            const response = await request(app)
                .delete(`/api/auth/sessions/${targetSession._id}`)
                .set("Authorization", `Bearer ${accessToken}`);

            expect(response.status).toBe(200);

            const updatedSession = await sessionModel.findById(
                targetSession._id
            );

            expect(updatedSession.revoked).toBe(true);
        });
    });

    describe("Logout", () => {
        it("revokes the current refresh session", async () => {
            const user = await createUser();

            const refreshToken = createRefreshToken();

            const refreshTokenHash = crypto
                .createHash("sha256")
                .update(refreshToken)
                .digest("hex");

            const session = await sessionModel.create({
                userId: user._id,
                refreshTokenHash,
                ip: "127.0.0.1",
                userAgent: "test-agent"
            });

            const response = await request(app)
                .get("/api/auth/logout")
                .set("Cookie", `refreshToken=${refreshToken}`);

            expect(response.status).toBe(200);

            const updatedSession = await sessionModel.findById(session._id);

            expect(updatedSession.revoked).toBe(true);
        });
    });

    describe("Logout all sessions", () => {
        it("revokes all sessions belonging to the authenticated user", async () => {
            const user = await createUser();

            await sessionModel.create([
                {
                    userId: user._id,
                    refreshTokenHash: crypto
                        .createHash("sha256")
                        .update("refresh-token-1")
                        .digest("hex"),
                    ip: "127.0.0.1",
                    userAgent: "test-agent-1"
                },
                {
                    userId: user._id,
                    refreshTokenHash: crypto
                        .createHash("sha256")
                        .update("refresh-token-2")
                        .digest("hex"),
                    ip: "127.0.0.1",
                    userAgent: "test-agent-2"
                },
                {
                    userId: user._id,
                    refreshTokenHash: crypto
                        .createHash("sha256")
                        .update("refresh-token-3")
                        .digest("hex"),
                    ip: "127.0.0.1",
                    userAgent: "test-agent-3"
                }
            ]);

            const accessToken = createAccessToken(user._id.toString());

            const response = await request(app)
                .get("/api/auth/logout-all")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(response.status).toBe(200);

            const sessions = await sessionModel.find({
                userId: user._id
            });

            expect(sessions).toHaveLength(3);
            expect(sessions.every((session) => session.revoked)).toBe(true);
        });
    });
});