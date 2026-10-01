import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("dotenv", () => ({
    default: {
        config: vi.fn()
    }
}));

const setValidEnv = () => {
    vi.stubEnv("MONGO_URI", "mongodb://test");
    vi.stubEnv("JWT_SECRET", "test-jwt-secret");

    // Gmail / Nodemailer OAuth
    vi.stubEnv("GOOGLE_CLIENT_ID", "test-client-id");
    vi.stubEnv("GOOGLE_CLIENT_SECRET", "test-client-secret");
    vi.stubEnv("GOOGLE_REFRESH_TOKEN", "test-refresh-token");
    vi.stubEnv("GOOGLE_USER", "test@example.com");

    // Google Login OAuth
    vi.stubEnv("GOOGLE_AUTH_CLIENT_ID", "test-auth-client-id");
    vi.stubEnv("GOOGLE_AUTH_CLIENT_SECRET", "test-auth-client-secret");

    vi.stubEnv("APP_BASE_URL", "http://localhost:3000");
    vi.stubEnv("PORT", "3000");
    vi.stubEnv("NODE_ENV", "development");
};

const removeEnv = (key) => {
    delete process.env[key];
};

describe("config", () => {
    beforeEach(() => {
        vi.resetModules();
        vi.unstubAllEnvs();
    });

    afterEach(() => {
        vi.unstubAllEnvs();
    });

    it("should load all required environment variables", async () => {
        setValidEnv();

        const { default: config } = await import("./config.js");

        expect(config).toEqual({
            MONGO_URI: "mongodb://test",
            JWT_SECRET: "test-jwt-secret",

            GOOGLE_CLIENT_ID: "test-client-id",
            GOOGLE_CLIENT_SECRET: "test-client-secret",
            GOOGLE_REFRESH_TOKEN: "test-refresh-token",
            GOOGLE_USER: "test@example.com",

            GOOGLE_AUTH_CLIENT_ID: "test-auth-client-id",
            GOOGLE_AUTH_CLIENT_SECRET: "test-auth-client-secret",

            APP_BASE_URL: "http://localhost:3000",
            PORT: 3000,
            NODE_ENV: "development"
        });
    });

    it("should throw when MONGO_URI is missing", async () => {
        setValidEnv();
        removeEnv("MONGO_URI");

        await expect(import("./config.js")).rejects.toThrow(
            "MONGO_URI is not defined in .env file"
        );
    });

    it("should throw when JWT_SECRET is missing", async () => {
        setValidEnv();
        removeEnv("JWT_SECRET");

        await expect(import("./config.js")).rejects.toThrow(
            "JWT_SECRET is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_CLIENT_ID is missing", async () => {
        setValidEnv();
        removeEnv("GOOGLE_CLIENT_ID");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_CLIENT_ID is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_CLIENT_SECRET is missing", async () => {
        setValidEnv();
        removeEnv("GOOGLE_CLIENT_SECRET");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_CLIENT_SECRET is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_REFRESH_TOKEN is missing", async () => {
        setValidEnv();
        removeEnv("GOOGLE_REFRESH_TOKEN");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_REFRESH_TOKEN is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_USER is missing", async () => {
        setValidEnv();
        removeEnv("GOOGLE_USER");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_USER is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_AUTH_CLIENT_ID is missing", async () => {
        setValidEnv();
        removeEnv("GOOGLE_AUTH_CLIENT_ID");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_AUTH_CLIENT_ID is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_AUTH_CLIENT_SECRET is missing", async () => {
        setValidEnv();
        removeEnv("GOOGLE_AUTH_CLIENT_SECRET");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_AUTH_CLIENT_SECRET is not defined in .env file"
        );
    });
});