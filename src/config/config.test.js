import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("dotenv", () => ({
    default: {
        config: vi.fn()
    }
}));

const setValidEnv = () => {
    vi.stubEnv("MONGO_URI", "mongodb://test");
    vi.stubEnv("JWT_SECRET", "test-jwt-secret");
    vi.stubEnv("GOOGLE_CLIENT_ID", "test-client-id");
    vi.stubEnv("GOOGLE_CLIENT_SECRET", "test-client-secret");
    vi.stubEnv("GOOGLE_REFRESH_TOKEN", "test-refresh-token");
    vi.stubEnv("GOOGLE_USER", "test@example.com");
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
            GOOGLE_USER: "test@example.com"
        });
    });

    it("should throw when MONGO_URI is missing", async () => {
        setValidEnv();
        vi.stubEnv("MONGO_URI", "");

        await expect(import("./config.js")).rejects.toThrow(
            "MONGO_URI is not defined in .env file"
        );
    });

    it("should throw when JWT_SECRET is missing", async () => {
        setValidEnv();
        vi.stubEnv("JWT_SECRET", "");

        await expect(import("./config.js")).rejects.toThrow(
            "JWT_SECRET is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_CLIENT_ID is missing", async () => {
        setValidEnv();
        vi.stubEnv("GOOGLE_CLIENT_ID", "");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_CLIENT_ID is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_CLIENT_SECRET is missing", async () => {
        setValidEnv();
        vi.stubEnv("GOOGLE_CLIENT_SECRET", "");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_CLIENT_SECRET is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_REFRESH_TOKEN is missing", async () => {
        setValidEnv();
        vi.stubEnv("GOOGLE_REFRESH_TOKEN", "");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_REFRESH_TOKEN is not defined in .env file"
        );
    });

    it("should throw when GOOGLE_USER is missing", async () => {
        setValidEnv();
        vi.stubEnv("GOOGLE_USER", "");

        await expect(import("./config.js")).rejects.toThrow(
            "GOOGLE_USER is not defined in .env file"
        );
    });
});