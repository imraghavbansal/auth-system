import { Router } from "express";
import * as authController from "../controllers/auth.controller.js";
import {
    registerSchema,
    loginSchema,
    verifyEmailSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
    changePasswordSchema,
    changeEmailSchema,
    resendOtpSchema,
    updateProfileSchema,
    verifyEmailChangeSchema,
    revokeSessionSchema
} from "../validations/auth.validation.js";
import { validate } from "../middleware/validate.middleware.js";
import { asyncHandler } from "../middleware/async-handler.middleware.js";



const authRouter = Router();

/**
 * POST /api/auth/register
 */
authRouter.post(
    "/register",
    validate(registerSchema),
    asyncHandler(authController.register)
);

/**
 * POST /api/auth/login
 */
authRouter.post(
    "/login",
    validate(loginSchema),
    asyncHandler(authController.login)
);

/**
 * GET /api/auth/get-me
 */
authRouter.get(
    "/get-me",
    asyncHandler(authController.getMe)
);

/**
 * GET /api/auth/refresh-token
 */
authRouter.get(
    "/refresh-token",
    asyncHandler(authController.refreshToken)
);

/**
 * GET /api/auth/logout
 */
authRouter.get(
    "/logout",
    asyncHandler(authController.logout)
);

/**
 * GET /api/auth/logout-all
 */
authRouter.get(
    "/logout-all",
    asyncHandler(authController.logoutAllSessions)
);

/**
 * GET /api/auth/verify-email
 */
authRouter.get(
    "/verify-email",
    validate(verifyEmailSchema),
    asyncHandler(authController.verifyEmail)
);

/**
 * POST /api/auth/forgot-password
 */
authRouter.post(
    "/forgot-password",
    validate(forgotPasswordSchema),
    asyncHandler(authController.forgotPassword)
);

/**
 * POST /api/auth/reset-password
 */
authRouter.post(
    "/reset-password",
    validate(resetPasswordSchema),
    asyncHandler(authController.resetPassword)
);

/**
 * POST /api/auth/change-password
 */
authRouter.post(
    "/change-password",
    validate(changePasswordSchema),
    asyncHandler(authController.changePassword)
);

/**
 * POST /api/auth/resend-otp
 */
authRouter.post(
    "/resend-otp",
    validate(resendOtpSchema),
    asyncHandler(authController.resendOtp)
);

/**
 * DELETE /api/auth/delete-account
 */
authRouter.delete(
    "/delete-account",
    asyncHandler(authController.deleteAccount)
);

/**
 * GET /api/auth/profile
 */
authRouter.get(
    "/profile",
    asyncHandler(authController.getProfile)
);

/**
 * PATCH /api/auth/profile
 */
authRouter.patch(
    "/profile",
    validate(updateProfileSchema),
    asyncHandler(authController.updateProfile)
);

/**
 * POST /api/auth/change-email
 */
authRouter.post(
    "/change-email",
    validate(changeEmailSchema),
    asyncHandler(authController.changeEmail)
);

/**
 * POST /api/auth/verify-email-change
 */
authRouter.post(
    "/verifyEmailChange",
    validate(verifyEmailChangeSchema),
    asyncHandler(authController.verifyEmailChange)
);

/**
 * GET /api/auth/getSessions
 */
authRouter.get(
    "/getSessions",
    asyncHandler(authController.getSessions)
);

/**
 * DELETE /api/auth/sessions/:sessionId
 */
authRouter.delete(
    "/sessions/:sessionId",
    validate(revokeSessionSchema),
    asyncHandler(authController.revokeSession)
);

export default authRouter;

