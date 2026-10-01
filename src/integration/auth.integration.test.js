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

vi.mock("../services/google-auth.service.js", () => ({
    generateGoogleState: vi.fn(),
    getGoogleAuthorizationUrl: vi.fn(),
    getGoogleUser: vi.fn()
}));

vi.mock("../services/github-auth.service.js", () => ({
    generateGithubState: vi.fn(),
    getGithubAuthorizationUrl: vi.fn(),
    exchangeGithubCode: vi.fn(),
    getGithubUser: vi.fn(),
    getGithubPrimaryEmail: vi.fn()
}));

import app from "../app.js";
import config from "../config/config.js";
import userModel from "../models/user.model.js";
import otpModel from "../models/otp.model.js";
import sessionModel from "../models/session.model.js";
import loginAttemptModel from "../models/login-attempt.model.js";
import emailQueue from "../queues/email.queue.js";

import {
    generateGoogleState,
    getGoogleAuthorizationUrl,
    getGoogleUser
} from "../services/google-auth.service.js";

import {
    generateGithubState,
    getGithubAuthorizationUrl,
    exchangeGithubCode,
    getGithubUser,
    getGithubPrimaryEmail
} from "../services/github-auth.service.js";

const TEST_PASSWORD = "Password123!";
const TEST_PASSWORD_2 = "NewPassword123!";

const createUser = async ({
    username = `testuser_${Date.now()}_${Math.random()}`,
    email = `test_${Date.now()}_${Math.random()}@example.com`,
    password = TEST_PASSWORD,
    verified = true,
    authProvider = "local",
    googleId,
    githubId
} = {}) => {
    const hashedPassword =
        authProvider === "local"
            ? await argon2.hash(password, {
                  type: argon2.argon2id
              })
            : null;

    return userModel.create({
        username,
        email,
        password: hashedPassword,
        verified,
        authProvider,
        ...(googleId ? { googleId } : {}),
        ...(githubId ? { githubId } : {})
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

const getRefreshTokenFromCookies = (cookies = []) => {
    const refreshCookie = cookies.find((cookie) =>
        cookie.startsWith("refreshToken=")
    );

    if (!refreshCookie) {
        return null;
    }

    return refreshCookie
        .split(";")[0]
        .replace("refreshToken=", "");
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

    generateGoogleState.mockReset();
    getGoogleAuthorizationUrl.mockReset();
    getGoogleUser.mockReset();

    generateGithubState.mockReset();
    getGithubAuthorizationUrl.mockReset();
    exchangeGithubCode.mockReset();
    getGithubUser.mockReset();
    getGithubPrimaryEmail.mockReset();

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

    describe("Google OAuth", () => {
        it("redirects to Google authentication and stores OAuth state", async () => {
            const state = "test-google-state";
            const authorizationUrl =
                "https://accounts.google.com/o/oauth2/v2/auth?test=true";

            generateGoogleState.mockReturnValue(state);
            getGoogleAuthorizationUrl.mockReturnValue(authorizationUrl);

            const response = await request(app)
                .get("/api/auth/google");

            expect(response.status).toBe(302);
            expect(response.headers.location).toBe(authorizationUrl);

            expect(generateGoogleState).toHaveBeenCalledTimes(1);
            expect(getGoogleAuthorizationUrl).toHaveBeenCalledWith(state);

            expect(response.headers["set-cookie"]).toBeDefined();

            const stateCookie = response.headers["set-cookie"].find(
                (cookie) => cookie.startsWith("googleOAuthState=")
            );

            expect(stateCookie).toBeDefined();
            expect(stateCookie).toContain(
                `googleOAuthState=${state}`
            );
            expect(stateCookie).toContain("HttpOnly");
            expect(stateCookie).toContain("SameSite=Lax");
        });

        it("rejects Google callback when OAuth state is missing", async () => {
            const response = await request(app)
                .get("/api/auth/google/callback")
                .query({
                    code: "test-code"
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe("Invalid OAuth state");

            expect(getGoogleUser).not.toHaveBeenCalled();
        });

        it("rejects Google callback when OAuth state is invalid", async () => {
            const response = await request(app)
                .get("/api/auth/google/callback")
                .set(
                    "Cookie",
                    "googleOAuthState=correct-state"
                )
                .query({
                    code: "test-code",
                    state: "wrong-state"
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe("Invalid OAuth state");

            expect(getGoogleUser).not.toHaveBeenCalled();
        });

        it("rejects Google callback when authorization code is missing", async () => {
            const response = await request(app)
                .get("/api/auth/google/callback")
                .set(
                    "Cookie",
                    "googleOAuthState=valid-state"
                )
                .query({
                    state: "valid-state"
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe(
                "Google authorization code is missing"
            );

            expect(getGoogleUser).not.toHaveBeenCalled();
        });

        it("rejects Google callback when Google authentication fails", async () => {
            getGoogleUser.mockRejectedValueOnce(
                new Error("Google token exchange failed")
            );

            const response = await request(app)
                .get("/api/auth/google/callback")
                .set(
                    "Cookie",
                    "googleOAuthState=valid-state"
                )
                .query({
                    code: "invalid-google-code",
                    state: "valid-state"
                });

            expect(response.status).toBe(401);
            expect(response.body.message).toBe(
                "Unable to authenticate with Google"
            );

            expect(getGoogleUser).toHaveBeenCalledWith(
                "invalid-google-code"
            );
        });

        it("rejects Google callback when Google account information is incomplete", async () => {
            getGoogleUser.mockResolvedValueOnce({
                googleId: null,
                email: "google@example.com",
                emailVerified: true
            });

            const response = await request(app)
                .get("/api/auth/google/callback")
                .set(
                    "Cookie",
                    "googleOAuthState=valid-state"
                )
                .query({
                    code: "google-code",
                    state: "valid-state"
                });

            expect(response.status).toBe(401);
            expect(response.body.message).toBe(
                "Google account information is incomplete"
            );
        });

        it("rejects Google callback when Google email is not verified", async () => {
            getGoogleUser.mockResolvedValueOnce({
                googleId: "google-user-123",
                email: "unverified@example.com",
                emailVerified: false
            });

            const response = await request(app)
                .get("/api/auth/google/callback")
                .set(
                    "Cookie",
                    "googleOAuthState=valid-state"
                )
                .query({
                    code: "google-code",
                    state: "valid-state"
                });

            expect(response.status).toBe(403);
            expect(response.body.message).toBe(
                "Google email is not verified"
            );

            const user = await userModel.findOne({
                email: "unverified@example.com"
            });

            expect(user).toBeNull();
        });

        it("creates a new Google user and session successfully", async () => {
            getGoogleUser.mockResolvedValueOnce({
                googleId: "google-new-user-123",
                email: "newgoogleuser@example.com",
                emailVerified: true,
                name: "New Google User"
            });

            const response = await request(app)
                .get("/api/auth/google/callback")
                .set(
                    "Cookie",
                    "googleOAuthState=valid-state"
                )
                .set(
                    "User-Agent",
                    "google-oauth-integration-test"
                )
                .query({
                    code: "google-code",
                    state: "valid-state"
                });

            expect(response.status).toBe(200);

            expect(response.body.message).toBe(
                "Google login successful"
            );

            expect(response.body.user).toEqual({
                username: "newgoogleuser",
                email: "newgoogleuser@example.com"
            });

            expect(response.body.accessToken).toBeDefined();

            const user = await userModel.findOne({
                googleId: "google-new-user-123"
            });

            expect(user).not.toBeNull();
            expect(user.email).toBe(
                "newgoogleuser@example.com"
            );
            expect(user.authProvider).toBe("google");
            expect(user.googleId).toBe(
                "google-new-user-123"
            );
            expect(user.verified).toBe(true);
            expect(user.password).toBeNull();

            const sessions = await sessionModel.find({
                userId: user._id
            });

            expect(sessions).toHaveLength(1);
            expect(sessions[0].revoked).toBe(false);
            expect(sessions[0].refreshTokenHash).toBeDefined();
            expect(sessions[0].userAgent).toBe(
                "google-oauth-integration-test"
            );

            const payload = jwt.verify(
                response.body.accessToken,
                config.JWT_SECRET
            );

            expect(payload.id).toBe(user._id.toString());

            expect(response.headers["set-cookie"]).toBeDefined();

            const refreshToken = getRefreshTokenFromCookies(
                response.headers["set-cookie"]
            );

            expect(refreshToken).not.toBeNull();

            const refreshTokenHash = crypto
                .createHash("sha256")
                .update(refreshToken)
                .digest("hex");

            expect(sessions[0].refreshTokenHash).toBe(
                refreshTokenHash
            );
        });

        it("logs in an existing Google user and creates a new session", async () => {
            const user = await createUser({
                username: "existing_google_user",
                email: "existinggoogle@example.com",
                authProvider: "google",
                googleId: "existing-google-id",
                verified: true
            });

            getGoogleUser.mockResolvedValueOnce({
                googleId: "existing-google-id",
                email: "existinggoogle@example.com",
                emailVerified: true,
                name: "Existing Google User"
            });

            const response = await request(app)
                .get("/api/auth/google/callback")
                .set(
                    "Cookie",
                    "googleOAuthState=valid-state"
                )
                .set(
                    "User-Agent",
                    "google-existing-user-test"
                )
                .query({
                    code: "google-code",
                    state: "valid-state"
                });

            expect(response.status).toBe(200);

            expect(response.body.user).toEqual({
                username: "existing_google_user",
                email: "existinggoogle@example.com"
            });

            expect(response.body.accessToken).toBeDefined();

            const users = await userModel.find({
                googleId: "existing-google-id"
            });

            expect(users).toHaveLength(1);
            expect(users[0]._id.toString()).toBe(
                user._id.toString()
            );

            const sessions = await sessionModel.find({
                userId: user._id
            });

            expect(sessions).toHaveLength(1);
            expect(sessions[0].revoked).toBe(false);
            expect(sessions[0].userAgent).toBe(
                "google-existing-user-test"
            );
        });

        it("rejects Google login when the email already belongs to a local account", async () => {
            const localUser = await createUser({
                username: "existing_local_user",
                email: "localaccount@example.com",
                authProvider: "local",
                verified: true
            });

            getGoogleUser.mockResolvedValueOnce({
                googleId: "google-conflict-id",
                email: "localaccount@example.com",
                emailVerified: true,
                name: "Local Account"
            });

            const response = await request(app)
                .get("/api/auth/google/callback")
                .set(
                    "Cookie",
                    "googleOAuthState=valid-state"
                )
                .query({
                    code: "google-code",
                    state: "valid-state"
                });

            expect(response.status).toBe(409);

            expect(response.body.message).toBe(
                "An account with this email already exists. Please log in with your existing account."
            );

            const user = await userModel.findById(
                localUser._id
            );

            expect(user).not.toBeNull();
            expect(user.authProvider).toBe("local");
            expect(user.googleId).toBeUndefined();

            const sessions = await sessionModel.find({
                userId: localUser._id
            });

            expect(sessions).toHaveLength(0);
        });
    });

    describe("GitHub OAuth", () => {
    it("redirects to GitHub authentication and stores OAuth state", async () => {
        const state = "test-github-state";

        const authorizationUrl =
            "https://github.com/login/oauth/authorize?test=true";

        generateGithubState.mockReturnValue(state);

        getGithubAuthorizationUrl.mockReturnValue(
            authorizationUrl
        );

        const response = await request(app)
            .get("/api/auth/github");

        expect(response.status).toBe(302);

        expect(response.headers.location).toBe(
            authorizationUrl
        );

        expect(generateGithubState).toHaveBeenCalledTimes(1);

        expect(getGithubAuthorizationUrl).toHaveBeenCalledWith(
            state
        );

        expect(response.headers["set-cookie"]).toBeDefined();

        const stateCookie = response.headers["set-cookie"].find(
            (cookie) =>
                cookie.startsWith("githubOAuthState=")
        );

        expect(stateCookie).toBeDefined();

        expect(stateCookie).toContain(
            `githubOAuthState=${state}`
        );

        expect(stateCookie).toContain("HttpOnly");
        expect(stateCookie).toContain("SameSite=Lax");
    });

    it("rejects GitHub callback when OAuth state is missing", async () => {
        const response = await request(app)
            .get("/api/auth/github/callback")
            .query({
                code: "test-code"
            });

        expect(response.status).toBe(400);

        expect(response.body.message).toBe(
            "Invalid OAuth state"
        );

        expect(exchangeGithubCode).not.toHaveBeenCalled();
    });

    it("rejects GitHub callback when OAuth state is invalid", async () => {
        const response = await request(app)
            .get("/api/auth/github/callback")
            .set(
                "Cookie",
                "githubOAuthState=correct-state"
            )
            .query({
                code: "test-code",
                state: "wrong-state"
            });

        expect(response.status).toBe(400);

        expect(response.body.message).toBe(
            "Invalid OAuth state"
        );

        expect(exchangeGithubCode).not.toHaveBeenCalled();
    });

    it("rejects GitHub callback when authorization code is missing", async () => {
        const response = await request(app)
            .get("/api/auth/github/callback")
            .set(
                "Cookie",
                "githubOAuthState=valid-state"
            )
            .query({
                state: "valid-state"
            });

        expect(response.status).toBe(400);

        expect(response.body.message).toBe(
            "GitHub authorization code is missing"
        );

        expect(exchangeGithubCode).not.toHaveBeenCalled();
    });

    it("rejects GitHub callback when GitHub authentication fails", async () => {
        exchangeGithubCode.mockRejectedValueOnce(
            new Error("GitHub token exchange failed")
        );

        const response = await request(app)
            .get("/api/auth/github/callback")
            .set(
                "Cookie",
                "githubOAuthState=valid-state"
            )
            .query({
                code: "invalid-github-code",
                state: "valid-state"
            });

        expect(response.status).toBe(401);

        expect(response.body.message).toBe(
            "Unable to authenticate with GitHub"
        );

        expect(exchangeGithubCode).toHaveBeenCalledWith(
            "invalid-github-code"
        );

        expect(getGithubUser).not.toHaveBeenCalled();
    });

    it("rejects GitHub callback when GitHub account information is incomplete", async () => {
        exchangeGithubCode.mockResolvedValueOnce(
            "github-access-token"
        );

        getGithubUser.mockResolvedValueOnce({
            id: null,
            login: "githubuser",
            name: "GitHub User"
        });

        getGithubPrimaryEmail.mockResolvedValueOnce(
            "github@example.com"
        );

        const response = await request(app)
            .get("/api/auth/github/callback")
            .set(
                "Cookie",
                "githubOAuthState=valid-state"
            )
            .query({
                code: "github-code",
                state: "valid-state"
            });

        expect(response.status).toBe(401);

        expect(response.body.message).toBe(
            "GitHub account information is incomplete"
        );

        expect(exchangeGithubCode).toHaveBeenCalledWith(
            "github-code"
        );

        expect(getGithubUser).toHaveBeenCalledWith(
            "github-access-token"
        );

        expect(getGithubPrimaryEmail).toHaveBeenCalledWith(
            "github-access-token"
        );
    });

    it("rejects GitHub callback when GitHub email information is incomplete", async () => {
        exchangeGithubCode.mockResolvedValueOnce(
            "github-access-token"
        );

        getGithubUser.mockResolvedValueOnce({
            id: "github-user-123",
            login: "githubuser",
            name: "GitHub User"
        });

        getGithubPrimaryEmail.mockResolvedValueOnce(null);

        const response = await request(app)
            .get("/api/auth/github/callback")
            .set(
                "Cookie",
                "githubOAuthState=valid-state"
            )
            .query({
                code: "github-code",
                state: "valid-state"
            });

        expect(response.status).toBe(401);

        expect(response.body.message).toBe(
            "GitHub account information is incomplete"
        );

        expect(exchangeGithubCode).toHaveBeenCalledWith(
            "github-code"
        );

        expect(getGithubUser).toHaveBeenCalledWith(
            "github-access-token"
        );

        expect(getGithubPrimaryEmail).toHaveBeenCalledWith(
            "github-access-token"
        );
    });

    it("creates a new GitHub user and session successfully", async () => {
        exchangeGithubCode.mockResolvedValueOnce(
            "github-access-token"
        );

        getGithubUser.mockResolvedValueOnce({
            id: "github-new-user-123",
            login: "newgithubuser",
            name: "New GitHub User"
        });

        getGithubPrimaryEmail.mockResolvedValueOnce(
            "newgithubuser@example.com"
        );

        const response = await request(app)
            .get("/api/auth/github/callback")
            .set(
                "Cookie",
                "githubOAuthState=valid-state"
            )
            .set(
                "User-Agent",
                "github-oauth-integration-test"
            )
            .query({
                code: "github-code",
                state: "valid-state"
            });

        expect(response.status).toBe(200);

        expect(response.body.message).toBe(
            "GitHub login successful"
        );

        expect(response.body.user).toEqual({
            username: "newgithubuser",
            email: "newgithubuser@example.com"
        });

        expect(response.body.accessToken).toBeDefined();

        const user = await userModel.findOne({
            githubId: "github-new-user-123"
        });

        expect(user).not.toBeNull();

        expect(user.email).toBe(
            "newgithubuser@example.com"
        );

        expect(user.authProvider).toBe("github");

        expect(user.githubId).toBe(
            "github-new-user-123"
        );

        expect(user.verified).toBe(true);

        expect(user.password).toBeNull();

        const sessions = await sessionModel.find({
            userId: user._id
        });

        expect(sessions).toHaveLength(1);

        expect(sessions[0].revoked).toBe(false);

        expect(sessions[0].refreshTokenHash).toBeDefined();

        expect(sessions[0].userAgent).toBe(
            "github-oauth-integration-test"
        );

        const payload = jwt.verify(
            response.body.accessToken,
            config.JWT_SECRET
        );

        expect(payload.id).toBe(
            user._id.toString()
        );

        expect(response.headers["set-cookie"]).toBeDefined();

        const refreshToken =
            getRefreshTokenFromCookies(
                response.headers["set-cookie"]
            );

        expect(refreshToken).not.toBeNull();

        const refreshTokenHash = crypto
            .createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        expect(sessions[0].refreshTokenHash).toBe(
            refreshTokenHash
        );

        expect(exchangeGithubCode).toHaveBeenCalledWith(
            "github-code"
        );

        expect(getGithubUser).toHaveBeenCalledWith(
            "github-access-token"
        );

        expect(getGithubPrimaryEmail).toHaveBeenCalledWith(
            "github-access-token"
        );
    });

    it("logs in an existing GitHub user and creates a new session", async () => {
        const user = await createUser({
            username: "existing_github_user",
            email: "existinggithub@example.com",
            authProvider: "github",
            githubId: "existing-github-id",
            verified: true
        });

        exchangeGithubCode.mockResolvedValueOnce(
            "github-access-token"
        );

        getGithubUser.mockResolvedValueOnce({
            id: "existing-github-id",
            login: "existinggithub",
            name: "Existing GitHub User"
        });

        getGithubPrimaryEmail.mockResolvedValueOnce(
            "existinggithub@example.com"
        );

        const response = await request(app)
            .get("/api/auth/github/callback")
            .set(
                "Cookie",
                "githubOAuthState=valid-state"
            )
            .set(
                "User-Agent",
                "github-existing-user-test"
            )
            .query({
                code: "github-code",
                state: "valid-state"
            });

        expect(response.status).toBe(200);

        expect(response.body.message).toBe(
            "GitHub login successful"
        );

        expect(response.body.user).toEqual({
            username: "existing_github_user",
            email: "existinggithub@example.com"
        });

        expect(response.body.accessToken).toBeDefined();

        const users = await userModel.find({
            githubId: "existing-github-id"
        });

        expect(users).toHaveLength(1);

        expect(users[0]._id.toString()).toBe(
            user._id.toString()
        );

        const sessions = await sessionModel.find({
            userId: user._id
        });

        expect(sessions).toHaveLength(1);

        expect(sessions[0].revoked).toBe(false);

        expect(sessions[0].userAgent).toBe(
            "github-existing-user-test"
        );

        expect(exchangeGithubCode).toHaveBeenCalledWith(
            "github-code"
        );

        expect(getGithubUser).toHaveBeenCalledWith(
            "github-access-token"
        );

        expect(getGithubPrimaryEmail).toHaveBeenCalledWith(
            "github-access-token"
        );
    });

    it("rejects GitHub login when the email already belongs to a local account", async () => {
        const localUser = await createUser({
            username: "existing_local_user",
            email: "localaccount@example.com",
            authProvider: "local",
            verified: true
        });

        exchangeGithubCode.mockResolvedValueOnce(
            "github-access-token"
        );

        getGithubUser.mockResolvedValueOnce({
            id: "github-conflict-id",
            login: "localaccount",
            name: "Local Account"
        });

        getGithubPrimaryEmail.mockResolvedValueOnce(
            "localaccount@example.com"
        );

        const response = await request(app)
            .get("/api/auth/github/callback")
            .set(
                "Cookie",
                "githubOAuthState=valid-state"
            )
            .query({
                code: "github-code",
                state: "valid-state"
            });

        expect(response.status).toBe(409);

        expect(response.body.message).toBe(
            "An account with this email already exists. Please log in with your existing account."
        );

        const user = await userModel.findById(
            localUser._id
        );

        expect(user).not.toBeNull();

        expect(user.authProvider).toBe("local");

        expect(user.githubId).toBeUndefined();

        const sessions = await sessionModel.find({
            userId: localUser._id
        });

        expect(sessions).toHaveLength(0);

        expect(exchangeGithubCode).toHaveBeenCalledWith(
            "github-code"
        );

        expect(getGithubUser).toHaveBeenCalledWith(
            "github-access-token"
        );

        expect(getGithubPrimaryEmail).toHaveBeenCalledWith(
            "github-access-token"
        );
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
                expiresAt: new Date(
                    Date.now() + 10 * 60 * 1000
                )
            });

            const response = await request(app)
                .get("/api/auth/verify-email")
                .send({
                    email: user.email,
                    otp: "999999"
                });

            expect(response.status).toBe(400);

            const updatedUser = await userModel.findById(
                user._id
            );

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

            const deletedOtp = await otpModel.findById(
                otp._id
            );

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
                expiresAt: new Date(
                    Date.now() + 10 * 60 * 1000
                )
            });

            const response = await request(app)
                .get("/api/auth/verify-email")
                .send({
                    email: user.email,
                    otp: otpValue
                });

            expect(response.status).toBe(200);

            const updatedUser = await userModel.findById(
                user._id
            );

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

            const updatedUser = await userModel.findById(
                user._id
            );

            expect(updatedUser.resetPasswordToken).not.toBeNull();
            expect(
                updatedUser.resetPasswordTokenExpiresAt
            ).not.toBeNull();

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

            const updatedUser = await userModel.findById(
                user._id
            );

            expect(updatedUser.resetPasswordToken).toBeNull();
            expect(
                updatedUser.resetPasswordTokenExpiresAt
            ).toBeNull();
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
            user.resetPasswordTokenExpiresAt = new Date(
                Date.now() - 1000
            );

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

            const updatedUser = await userModel.findById(
                user._id
            );

            expect(
                updatedUser.resetPasswordToken
            ).toBeNull();

            expect(
                updatedUser.resetPasswordTokenExpiresAt
            ).toBeNull();

            const passwordMatches = await argon2.verify(
                updatedUser.password,
                TEST_PASSWORD_2
            );

            expect(passwordMatches).toBe(true);

            const sessions = await sessionModel.find({
                userId: user._id
            });

            expect(sessions).toHaveLength(2);
            expect(
                sessions.every((session) => session.revoked)
            ).toBe(true);
        });
    });

    describe("Change password", () => {
        it("rejects an incorrect current password", async () => {
            const user = await createUser();

            const accessToken = createAccessToken(
                user._id.toString()
            );

            const response = await request(app)
                .post("/api/auth/change-password")
                .set(
                    "Authorization",
                    `Bearer ${accessToken}`
                )
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

            const accessToken = createAccessToken(
                user._id.toString()
            );

            const response = await request(app)
                .post("/api/auth/change-password")
                .set(
                    "Authorization",
                    `Bearer ${accessToken}`
                )
                .send({
                    currentPassword: TEST_PASSWORD,
                    newPassword: TEST_PASSWORD_2
                });

            expect(response.status).toBe(200);

            const updatedUser = await userModel.findById(
                user._id
            );

            const passwordMatches = await argon2.verify(
                updatedUser.password,
                TEST_PASSWORD_2
            );

            expect(passwordMatches).toBe(true);

            const sessions = await sessionModel.find({
                userId: user._id
            });

            expect(sessions).toHaveLength(2);
            expect(
                sessions.every((session) => session.revoked)
            ).toBe(true);
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

            const accessToken = createAccessToken(
                user._id.toString()
            );

            const response = await request(app)
                .delete(
                    `/api/auth/sessions/${targetSession._id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${accessToken}`
                );

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
                .set(
                    "Cookie",
                    `refreshToken=${refreshToken}`
                );

            expect(response.status).toBe(200);

            const updatedSession = await sessionModel.findById(
                session._id
            );

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

            const accessToken = createAccessToken(
                user._id.toString()
            );

            const response = await request(app)
                .get("/api/auth/logout-all")
                .set(
                    "Authorization",
                    `Bearer ${accessToken}`
                );

            expect(response.status).toBe(200);

            const sessions = await sessionModel.find({
                userId: user._id
            });

            expect(sessions).toHaveLength(3);
            expect(
                sessions.every((session) => session.revoked)
            ).toBe(true);
        });
    });
});