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
import { authenticateUser } from "../middleware/auth.middleware.js";

const authRouter = Router();

/**
 * @openapi
 * /api/auth/register:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Register a new user
 *     description: Creates a new user account and sends an email verification OTP.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - username
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 example: raghav
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 6
 *                 example: Password123!
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User registered successfully
 *                 user:
 *                   type: object
 *                   properties:
 *                     username:
 *                       type: string
 *                     email:
 *                       type: string
 *                       format: email
 *                     verified:
 *                       type: boolean
 *                       example: false
 *       400:
 *         description: Invalid request data
 *       409:
 *         description: Username or email already exists
 *       500:
 *         description: Internal server error
 */
authRouter.post(
    "/register",
    validate(registerSchema),
    asyncHandler(authController.register)
);

/**
 * @openapi
 * /api/auth/login:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Log in a user
 *     description: Authenticates a verified user, creates a session and returns an access token.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: Password123!
 *     responses:
 *       200:
 *         description: User logged in successfully
 *       401:
 *         description: Invalid email or password
 *       403:
 *         description: Email is not verified
 *       429:
 *         description: Too many failed login attempts
 *       500:
 *         description: Internal server error
 */
authRouter.post(
    "/login",
    validate(loginSchema),
    asyncHandler(authController.login)
);

/**
 * @openapi
 * /api/auth/get-me:
 *   get:
 *     tags:
 *       - Authentication
 *     summary: Get the authenticated user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User fetched successfully
 *       401:
 *         description: Authentication required or token is invalid
 */
authRouter.get(
    "/get-me",
    asyncHandler(authenticateUser),
    asyncHandler(authController.getMe)
);

/**
 * @openapi
 * /api/auth/refresh-token:
 *   get:
 *     tags:
 *       - Authentication
 *     summary: Refresh an access token
 *     description: Uses the refresh token stored in the HTTP-only cookie to issue a new access token and rotate the refresh token.
 *     responses:
 *       200:
 *         description: Access token refreshed successfully
 *       401:
 *         description: Refresh token missing or invalid
 */
authRouter.get(
    "/refresh-token",
    asyncHandler(authController.refreshToken)
);

/**
 * @openapi
 * /api/auth/logout:
 *   get:
 *     tags:
 *       - Authentication
 *     summary: Log out the current session
 *     description: Revokes the session associated with the refresh token cookie.
 *     responses:
 *       200:
 *         description: User logged out successfully
 *       401:
 *         description: Refresh token missing or invalid
 */
authRouter.get(
    "/logout",
    asyncHandler(authController.logout)
);

/**
 * @openapi
 * /api/auth/logout-all:
 *   get:
 *     tags:
 *       - Authentication
 *     summary: Log out all sessions
 *     security:
 *       - bearerAuth: []
 *     description: Revokes all active sessions belonging to the authenticated user.
 *     responses:
 *       200:
 *         description: User logged out from all sessions successfully
 *       401:
 *         description: Authentication required or token is invalid
 */
authRouter.get(
    "/logout-all",
    asyncHandler(authenticateUser),
    asyncHandler(authController.logoutAllSessions)
);

/**
 * @openapi
 * /api/auth/verify-email:
 *   get:
 *     tags:
 *       - Authentication
 *     summary: Verify an email address
 *     description: Verifies the user's email using the six-character OTP generated during registration.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - otp
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               otp:
 *                 type: string
 *                 minLength: 6
 *                 maxLength: 6
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: Email verified successfully
 *       400:
 *         description: Invalid or expired OTP
 *       404:
 *         description: User not found
 */
authRouter.get(
    "/verify-email",
    validate(verifyEmailSchema),
    asyncHandler(authController.verifyEmail)
);

/**
 * @openapi
 * /api/auth/forgot-password:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Request a password reset
 *     description: Generates a password reset token and sends a reset link to the user's email.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: Password reset link sent successfully
 *       404:
 *         description: User not found
 */
authRouter.post(
    "/forgot-password",
    validate(forgotPasswordSchema),
    asyncHandler(authController.forgotPassword)
);

/**
 * @openapi
 * /api/auth/reset-password:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Reset a user's password
 *     description: Resets the password using a valid password reset token and revokes all active sessions.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - email
 *               - password
 *             properties:
 *               token:
 *                 type: string
 *                 example: 9b6f0d5e...
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 6
 *                 example: NewPassword123!
 *     responses:
 *       200:
 *         description: Password reset successfully
 *       400:
 *         description: Invalid or expired reset token
 *       404:
 *         description: User not found
 */
authRouter.post(
    "/reset-password",
    validate(resetPasswordSchema),
    asyncHandler(authController.resetPassword)
);

/**
 * @openapi
 * /api/auth/change-password:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Change the authenticated user's password
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 format: password
 *                 minLength: 6
 *                 example: Password123!
 *               newPassword:
 *                 type: string
 *                 format: password
 *                 minLength: 6
 *                 example: NewPassword123!
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       401:
 *         description: Current password is incorrect or authentication failed
 */
authRouter.post(
    "/change-password",
    validate(changePasswordSchema),
    asyncHandler(authenticateUser),
    asyncHandler(authController.changePassword)
);

/**
 * @openapi
 * /api/auth/resend-otp:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Resend email verification OTP
 *     description: Generates and sends a new email verification OTP, subject to the resend cooldown.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *       400:
 *         description: Email is already verified
 *       404:
 *         description: User not found
 *       429:
 *         description: OTP resend cooldown is active
 */
authRouter.post(
    "/resend-otp",
    validate(resendOtpSchema),
    asyncHandler(authController.resendOtp)
);

/**
 * @openapi
 * /api/auth/delete-account:
 *   delete:
 *     tags:
 *       - Authentication
 *     summary: Delete the authenticated user's account
 *     security:
 *       - bearerAuth: []
 *     description: Deletes the user account along with its sessions and OTP records.
 *     responses:
 *       200:
 *         description: Account deleted successfully
 *       401:
 *         description: Authentication required or token is invalid
 */
authRouter.delete(
    "/delete-account",
    asyncHandler(authenticateUser),
    asyncHandler(authController.deleteAccount)
);

/**
 * @openapi
 * /api/auth/profile:
 *   get:
 *     tags:
 *       - Authentication
 *     summary: Get the authenticated user's profile
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *       401:
 *         description: Authentication required or token is invalid
 */
authRouter.get(
    "/profile",
    asyncHandler(authenticateUser),
    asyncHandler(authController.getProfile)
);

/**
 * @openapi
 * /api/auth/profile:
 *   patch:
 *     tags:
 *       - Authentication
 *     summary: Update the authenticated user's profile
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *             properties:
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 example: newusername
 *     responses:
 *       200:
 *         description: User profile updated successfully
 *       401:
 *         description: Authentication required or token is invalid
 */
authRouter.patch(
    "/profile",
    validate(updateProfileSchema),
    asyncHandler(authenticateUser),
    asyncHandler(authController.updateProfile)
);

/**
 * @openapi
 * /api/auth/change-email:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Request an email address change
 *     security:
 *       - bearerAuth: []
 *     description: Sends an OTP to the new email address for verification.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: newemail@example.com
 *     responses:
 *       200:
 *         description: OTP sent to new email address
 *       400:
 *         description: New email is the same as the current email
 *       409:
 *         description: Email is already in use
 *       401:
 *         description: Authentication required or token is invalid
 */
authRouter.post(
    "/change-email",
    validate(changeEmailSchema),
    asyncHandler(authenticateUser),
    asyncHandler(authController.changeEmail)
);

/**
 * @openapi
 * /api/auth/verify-email-change:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Verify an email address change
 *     security:
 *       - bearerAuth: []
 *     description: Verifies the OTP sent to the new email address and updates the user's email.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - otp
 *               - email
 *             properties:
 *               otp:
 *                 type: string
 *                 minLength: 6
 *                 maxLength: 6
 *                 example: "123456"
 *               email:
 *                 type: string
 *                 format: email
 *                 example: newemail@example.com
 *     responses:
 *       200:
 *         description: Email changed successfully
 *       400:
 *         description: Invalid or expired OTP
 *       409:
 *         description: Email is already in use
 *       401:
 *         description: Authentication required or token is invalid
 */
authRouter.post(
    "/verify-email-change",
    validate(verifyEmailChangeSchema),
    asyncHandler(authenticateUser),
    asyncHandler(authController.verifyEmailChange)
);

/**
 * @openapi
 * /api/auth/getSessions:
 *   get:
 *     tags:
 *       - Authentication
 *     summary: Get active sessions
 *     security:
 *       - bearerAuth: []
 *     description: Returns all non-revoked sessions belonging to the authenticated user.
 *     responses:
 *       200:
 *         description: Sessions fetched successfully
 *       401:
 *         description: Authentication required or token is invalid
 */
authRouter.get(
    "/getSessions",
    asyncHandler(authenticateUser),
    asyncHandler(authController.getSessions)
);

/**
 * @openapi
 * /api/auth/sessions/{sessionId}:
 *   delete:
 *     tags:
 *       - Authentication
 *     summary: Revoke a specific session
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: sessionId
 *         in: path
 *         required: true
 *         description: ID of the session to revoke
 *         schema:
 *           type: string
 *         example: 65f123456789abcdef123456
 *     responses:
 *       200:
 *         description: Session revoked successfully
 *       404:
 *         description: Session not found
 *       401:
 *         description: Authentication required or token is invalid
 */
authRouter.delete(
    "/sessions/:sessionId",
    validate(revokeSessionSchema),
    asyncHandler(authenticateUser),
    asyncHandler(authController.revokeSession)
);

export default authRouter;