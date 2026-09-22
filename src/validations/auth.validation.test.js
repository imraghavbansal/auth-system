import { describe, it, expect } from "vitest";
import {
    registerSchema,
    loginSchema,
    verifyEmailSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
    changePasswordSchema,
    resendOtpSchema,
    updateProfileSchema,
    changeEmailSchema,
    verifyEmailChangeSchema,
    revokeSessionSchema
} from "../validations/auth.validation.js";

describe("registerSchema", () => {
    it("should accept valid registration data", () => {
        const result = registerSchema.safeParse({
            body: {
                email: "test@example.com",
                username: "raghav",
                password: "password123"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject invalid registration data", () => {
        const result = registerSchema.safeParse({
            body: {
                email: "not-an-email",
                username: "ab",
                password: "123"
            }
        });

        expect(result.success).toBe(false);
    });
});
describe("loginSchema", () => {
    it("should accept valid login data", () => {
        const result = loginSchema.safeParse({
            body: {
                email: "test@example.com",
                password: "password123"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject invalid login data", () => {
        const result = loginSchema.safeParse({
            body: {
                email: "invalid-email",
                password: "123"
            }
        });

        expect(result.success).toBe(false);
    });
});

describe("verifyEmailSchema", () => {
    it("should accept a valid email and OTP", () => {
        const result = verifyEmailSchema.safeParse({
            body: {
                email: "test@example.com",
                otp: "123456"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject an invalid OTP", () => {
        const result = verifyEmailSchema.safeParse({
            body: {
                email: "test@example.com",
                otp: "12345"
            }
        });

        expect(result.success).toBe(false);
    });
});
describe("forgotPasswordSchema", () => {
    it("should accept a valid email", () => {
        const result = forgotPasswordSchema.safeParse({
            body: {
                email: "test@example.com"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject an invalid email", () => {
        const result = forgotPasswordSchema.safeParse({
            body: {
                email: "invalid-email"
            }
        });

        expect(result.success).toBe(false);
    });
});

describe("resetPasswordSchema", () => {
    it("should accept valid reset password data", () => {
        const result = resetPasswordSchema.safeParse({
            body: {
                token: "reset-token-123",
                email: "test@example.com",
                password: "newpassword123"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject missing reset token", () => {
        const result = resetPasswordSchema.safeParse({
            body: {
                token: "",
                email: "test@example.com",
                password: "newpassword123"
            }
        });

        expect(result.success).toBe(false);
    });
});

describe("changePasswordSchema", () => {
    it("should accept valid password change data", () => {
        const result = changePasswordSchema.safeParse({
            body: {
                currentPassword: "oldpassword",
                newPassword: "newpassword"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject passwords shorter than 6 characters", () => {
        const result = changePasswordSchema.safeParse({
            body: {
                currentPassword: "12345",
                newPassword: "12345"
            }
        });

        expect(result.success).toBe(false);
    });
});

describe("resendOtpSchema", () => {
    it("should accept a valid email", () => {
        const result = resendOtpSchema.safeParse({
            body: {
                email: "test@example.com"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject an invalid email", () => {
        const result = resendOtpSchema.safeParse({
            body: {
                email: "invalid-email"
            }
        });

        expect(result.success).toBe(false);
    });
});

describe("updateProfileSchema", () => {
    it("should accept a valid username", () => {
        const result = updateProfileSchema.safeParse({
            body: {
                username: "raghav"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject usernames shorter than 3 characters", () => {
        const result = updateProfileSchema.safeParse({
            body: {
                username: "ab"
            }
        });

        expect(result.success).toBe(false);
    });
});

describe("changeEmailSchema", () => {
    it("should accept a valid email", () => {
        const result = changeEmailSchema.safeParse({
            body: {
                email: "newemail@example.com"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject an invalid email", () => {
        const result = changeEmailSchema.safeParse({
            body: {
                email: "invalid-email"
            }
        });

        expect(result.success).toBe(false);
    });
});

describe("verifyEmailChangeSchema", () => {
    it("should accept valid email change verification data", () => {
        const result = verifyEmailChangeSchema.safeParse({
            body: {
                otp: "123456",
                email: "newemail@example.com"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject an invalid OTP", () => {
        const result = verifyEmailChangeSchema.safeParse({
            body: {
                otp: "12345",
                email: "newemail@example.com"
            }
        });

        expect(result.success).toBe(false);
    });
});

describe("revokeSessionSchema", () => {
    it("should accept a valid session ID", () => {
        const result = revokeSessionSchema.safeParse({
            params: {
                sessionId: "session-123"
            }
        });

        expect(result.success).toBe(true);
    });

    it("should reject an empty session ID", () => {
        const result = revokeSessionSchema.safeParse({
            params: {
                sessionId: ""
            }
        });

        expect(result.success).toBe(false);
    });
});