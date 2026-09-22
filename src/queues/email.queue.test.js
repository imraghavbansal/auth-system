import { describe, it, expect, vi, beforeEach } from "vitest";

const { QueueMock } = vi.hoisted(() => ({
    QueueMock: vi.fn()
}));

vi.mock("bullmq", () => ({
    Queue: QueueMock
}));

vi.mock("../config/redis.js", () => ({
    default: {
        status: "ready"
    }
}));

describe("emailQueue", () => {
    beforeEach(() => {
        vi.resetModules();
        vi.clearAllMocks();
    });

    it("should create an email queue with the correct configuration", async () => {
        await import("./email.queue.js");

        expect(QueueMock).toHaveBeenCalledWith(
            "email",
            {
                connection: {
                    status: "ready"
                },
                defaultJobOptions: {
                    attempts: 3,
                    backoff: {
                        type: "exponential",
                        delay: 5000
                    }
                }
            }
        );
    });
});