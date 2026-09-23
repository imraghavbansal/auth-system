import { z } from "zod";

export const registerSchema = z.object({
    body: z.object({
        email: z.string().email({
            message: "Invalid email address"
        }),
        username: z.string().min(3, {
            message: "Username must be at least 3 characters long"
        }),
        password: z.string().min(6, {
            message: "Password must be at least 6 characters long"
        })
    })
});

export const loginSchema = z.object({
    body: z.object({
        email: z.string().email({
            message: "Invalid email address"
        }),
        password: z.string().min(6, {
            message: "Password must be at least 6 characters long"
        })
    })
});

export const verifyEmailSchema = z.object({

    body: z.object({

        email: z.string().email({
            message: "Invalid email address"
        }),

        otp: z.string().length(6, {
            message: "OTP must be 6 characters long"
        })

    })

});

export const forgotPasswordSchema = z.object({

    body: z.object({

        email: z.string().email({
            message: "Invalid email address"
        })

    })

});

export const resetPasswordSchema = z.object({

    body: z.object({

        token: z.string().min(1, {
            message: "Reset token is required"
        }),

        email: z.string().email({
            message: "Invalid email address"
        }),

        password: z.string().min(6, {
            message: "Password must be at least 6 characters long"
        })

    })

});

export const changePasswordSchema = z.object({

    body: z.object({

        currentPassword: z.string().min(6, {
            message: "Current password must be at least 6 characters long"
        }),

        newPassword: z.string().min(6, {
            message: "New password must be at least 6 characters long"
        })

    })

});

export const resendOtpSchema = z.object({

    body: z.object({

        email: z.string().email({
            message: "Invalid email address"
        })

    })

});

export const updateProfileSchema = z.object({

    body: z.object({

        username: z.string().min(3, {
            message: "Username must be at least 3 characters long"
        })

    })

});

export const changeEmailSchema = z.object({

    body: z.object({

        email: z.string().email({
            message: "Invalid email address"
        })

    })

});

export const verifyEmailChangeSchema = z.object({

    body: z.object({

        otp: z.string().length(6, {
            message: "OTP must be 6 characters long"
        }),

        email: z.string().email({
            message: "Invalid email address"
        })

    })

});

export const revokeSessionSchema = z.object({

    params: z.object({

        sessionId: z.string().min(1, {
            message: "Session ID is required"
        })

    })

});