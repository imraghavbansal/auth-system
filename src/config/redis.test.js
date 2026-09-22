import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { on, IORedisMock } = vi.hoisted(() => {
    const on = vi.fn();

    const IORedisMock = vi.fn(function (...args) {
        this.args = args;
        this.on = on;
    });

    return {
        on,
        IORedisMock
    };
});

vi.mock("ioredis", () => ({
    default: IORedisMock
}));

describe("redis", () => {
    beforeEach(() => {
        vi.resetModules();
        vi.clearAllMocks();
        vi.unstubAllEnvs();
    });

    afterEach(() => {
        vi.unstubAllEnvs();
    });

    it("should create Redis connection using REDIS_URL", async () => {
        vi.stubEnv(
            "REDIS_URL",
            "redis://test-redis:6379"
        );

        await import("./redis.js");

        expect(IORedisMock).toHaveBeenCalledWith(
            "redis://test-redis:6379",
            {
                maxRetriesPerRequest: null
            }
        );
    });

    it("should use localhost Redis when REDIS_URL is not defined", async () => {
        vi.stubEnv("REDIS_URL", "");

        await import("./redis.js");

        expect(IORedisMock).toHaveBeenCalledWith(
            "redis://127.0.0.1:6379",
            {
                maxRetriesPerRequest: null
            }
        );
    });

    it("should register connect and error event handlers", async () => {
        vi.stubEnv(
            "REDIS_URL",
            "redis://test-redis:6379"
        );

        await import("./redis.js");

        expect(on).toHaveBeenCalledTimes(2);

        expect(on).toHaveBeenCalledWith(
            "connect",
            expect.any(Function)
        );

        expect(on).toHaveBeenCalledWith(
            "error",
            expect.any(Function)
        );
    });
});