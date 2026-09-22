import { describe, it, expect, vi, beforeEach } from "vitest";

const { sendMail, verify } = vi.hoisted(() => ({
    sendMail: vi.fn(),
    verify: vi.fn()
}));

vi.mock("nodemailer", () => ({
    default: {
        createTransport: vi.fn(() => ({
            sendMail,
            verify
        }))
    }
}));

vi.mock("../config/config.js", () => ({
    default: {
        GOOGLE_USER: "test@example.com",
        GOOGLE_CLIENT_ID: "client-id",
        GOOGLE_CLIENT_SECRET: "client-secret",
        GOOGLE_REFRESH_TOKEN: "refresh-token"
    }
}));

import { sendEmail } from "./email.service.js";

describe("sendEmail", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("should send an email with the correct data", async () => {
        const emailInfo = {
            messageId: "test-message-id"
        };

        sendMail.mockResolvedValue(emailInfo);

        const result = await sendEmail(
            "recipient@example.com",
            "Test subject",
            "Test email",
            "<p>Test email</p>"
        );

        expect(sendMail).toHaveBeenCalledWith({
            from: '"Your Name" <test@example.com>',
            to: "recipient@example.com",
            subject: "Test subject",
            text: "Test email",
            html: "<p>Test email</p>"
        });

        expect(result).toBe(emailInfo);
    });

    it("should return the email information when sending succeeds", async () => {
        const emailInfo = {
            messageId: "test-message-id"
        };

        sendMail.mockResolvedValue(emailInfo);

        const result = await sendEmail(
            "recipient@example.com",
            "Test subject",
            "Test email",
            "<p>Test email</p>"
        );

        expect(result).toEqual(emailInfo);
    });

    it("should throw an AppError when sending email fails", async () => {
        sendMail.mockRejectedValue(
            new Error("SMTP connection failed")
        );

        await expect(
            sendEmail(
                "recipient@example.com",
                "Test subject",
                "Test email",
                "<p>Test email</p>"
            )
        ).rejects.toMatchObject({
            message: "Unable to send email. Please try again later.",
            statusCode: 503
        });
    });
});