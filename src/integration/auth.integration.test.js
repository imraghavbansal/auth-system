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
import userModel from "../models/user.model.js";
import otpModel from "../models/otp.model.js";

describe("POST /api/auth/register", () => {
    beforeAll(async () => {
        if (!process.env.MONGO_TEST_URI) {
            throw new Error("MONGO_TEST_URI is not defined");
        }

        await mongoose.connect(process.env.MONGO_TEST_URI);
    });

    afterEach(async () => {
        await userModel.deleteMany({});
        await otpModel.deleteMany({});
    });

    afterAll(async () => {
        if (mongoose.connection.readyState === 1) {
            await mongoose.connection.dropDatabase();
            await mongoose.connection.close();
        }
    });

    it("should register a new user and create an email verification OTP", async () => {
        const response = await request(app)
            .post("/api/auth/register")
            .send({
                username: "integrationuser",
                email: "integration@example.com",
                password: "password123"
            });

        expect(response.status).toBe(201);

        expect(response.body).toEqual({
            message: "User registered successfully",
            user: {
                username: "integrationuser",
                email: "integration@example.com",
                verified: false
            }
        });

        const user = await userModel.findOne({
            email: "integration@example.com"
        });

        expect(user).not.toBeNull();
        expect(user.username).toBe("integrationuser");
        expect(user.email).toBe("integration@example.com");
        expect(user.verified).toBe(false);

        expect(user.password).not.toBe("password123");

        const passwordMatches = await argon2.verify(
            user.password,
            "password123"
        );

        expect(passwordMatches).toBe(true);

        const otp = await otpModel.findOne({
            email: "integration@example.com",
            user: user._id,
            purpose: "EMAIL_VERIFICATION"
        });

        expect(otp).not.toBeNull();

        expect(otp.otpHash).toMatch(/^[a-f0-9]{64}$/);

        expect(otp.expiresAt.getTime()).toBeGreaterThan(Date.now());

        expect(otp.expiresAt.getTime()).toBeLessThanOrEqual(
            Date.now() + 10 * 60 * 1000
        );
    });

    it("should reject registration when the email is already registered", async () => {
        await userModel.create({
            username: "existinguser",
            email: "existing@example.com",
            password: "already-hashed-password",
            verified: false
        });

        const response = await request(app)
            .post("/api/auth/register")
            .send({
                username: "newuser",
                email: "existing@example.com",
                password: "password123"
            });

        expect(response.status).toBe(409);

        expect(response.body).toEqual({
            message: "Username or Email already exists"
        });

        const users = await userModel.find({
            email: "existing@example.com"
        });

        expect(users).toHaveLength(1);

        const otpCount = await otpModel.countDocuments({
            email: "existing@example.com"
        });

        expect(otpCount).toBe(0);
    });
});