import { describe, it, expect, vi, beforeEach } from "vitest";

const {
    WorkerMock,
    sendEmailMock,
    redis
} = vi.hoisted(() => {
    const sendEmailMock = vi.fn();

    const redis = {
        quit: vi.fn()
    };

    const WorkerMock = vi.fn(function () {
        this.on = vi.fn();
        this.close = vi.fn();
    });

    return {
        WorkerMock,
        sendEmailMock,
        redis
    };
});

vi.mock("bullmq", () => ({
    Worker: WorkerMock
}));

vi.mock("../config/redis.js", () => ({
    default: redis
}));

vi.mock("../services/email.service.js", () => ({
    sendEmail: sendEmailMock
}));

describe("emailWorker", () => {
    beforeEach(() => {
        vi.resetModules();
        vi.clearAllMocks();
    });

    it("should create an email worker with the correct queue and Redis connection", async () => {
        await import("./email.worker.js");

        expect(WorkerMock).toHaveBeenCalledWith(
            "email",
            expect.any(Function),
            {
                connection: redis
            }
        );
    });

    it("should process an email job and call sendEmail with job data", async () => {
        await import("./email.worker.js");

        const workerInstance = WorkerMock.mock.instances[0];

        const workerHandler = WorkerMock.mock.calls[0][1];

        const job = {
            id: "job-1",
            data: {
                to: "test@example.com",
                subject: "Test subject",
                text: "Test email",
                html: "<p>Test email</p>"
            }
        };

        sendEmailMock.mockResolvedValue({
            messageId: "message-1"
        });

        await workerHandler(job);

        expect(sendEmailMock).toHaveBeenCalledWith(
            "test@example.com",
            "Test subject",
            "Test email",
            "<p>Test email</p>"
        );

        expect(workerInstance).toBeDefined();
    });

    it("should propagate email sending errors", async () => {
        await import("./email.worker.js");

        const workerHandler = WorkerMock.mock.calls[0][1];

        const job = {
            id: "job-2",
            data: {
                to: "test@example.com",
                subject: "Test subject",
                text: "Test email",
                html: "<p>Test email</p>"
            }
        };

        sendEmailMock.mockRejectedValue(
            new Error("Email sending failed")
        );

        await expect(workerHandler(job)).rejects.toThrow(
            "Email sending failed"
        );
    });
});