import { generateOtp, getOtpHtml } from "./utils.js";
import { describe, it, expect } from "vitest";

describe("generateOtp", () => {
    it("should generate a 6-digit OTP", () => {
        const otp = generateOtp();

        expect(otp).toHaveLength(6);
        expect(otp).toMatch(/^\d{6}$/);
        expect(typeof otp).toBe("string");
    });
});

describe("getOtpHtml", () => {
    it("should include the OTP in the generated HTML", () => {
        const otp = "123456";

        const html = getOtpHtml(otp);

        expect(html).toContain(otp);
    });
});