import {Router} from "express";
import * as authController from "../controllers/auth.controller.js";
import {registerSchema, loginSchema, verifyEmailSchema, forgotPasswordSchema, resetPasswordSchema, changePasswordSchema, changeEmailSchema, resendOtpSchema, updateProfileSchema, verifyEmailChangeSchema, revokeSessionSchema } from "../validations/auth.validation.js";
import {validate} from "../middleware/validate.middleware.js";
const authRouter = Router();


/**
 POST /api/auth/register
 */
authRouter.post("/register", validate(registerSchema) ,authController.register);

/** POST /api/auth/login
 */
authRouter.post("/login", validate(loginSchema) ,authController.login);


/**
 GET /api/auth/get-me
 */
authRouter.get("/get-me", authController.getMe); 


/**
 * GET /api/auth/refresh-token
 */
authRouter.get("/refresh-token", authController.refreshToken);


/**
 * GET /api/auth/logout
 */
authRouter.get("/logout", authController.logout);


/**
 * GET /api/auth/logout-all
 */
authRouter.get("/logout-all", authController.logoutAllSessions);


/**
 * GET /api/auth/verify-email
 */
authRouter.get("/verify-email", validate(verifyEmailSchema) ,authController.verifyEmail);


/** * POST /api/auth/forgot-password
 */
authRouter.post("/forgot-password", validate(forgotPasswordSchema) ,authController.forgotPassword);


/** * POST /api/auth/reset-password
 */
authRouter.post("/reset-password", validate(resetPasswordSchema) ,authController.resetPassword);


/** * POST /api/auth/change-password
 */
authRouter.post("/change-password", validate(changePasswordSchema) ,authController.changePassword);


/** * POST /api/auth/resend-otp
 */
authRouter.post("/resend-otp", validate(resendOtpSchema) ,authController.resendOtp);


/** * DELETE /api/auth/delete-account
 */
authRouter.delete("/delete-account", authController.deleteAccount);


/** * GET /api/auth/profile
 */
authRouter.get("/profile", authController.getProfile);


/** * PATCH /api/auth/profile
 */
authRouter.patch("/profile", validate(updateProfileSchema) ,authController.updateProfile);


/** * POST /api/auth/change-email
 */
authRouter.post("/change-email", validate(changeEmailSchema) ,authController.changeEmail);


/** * POST /api/auth/verify-email-change
 */
authRouter.post("/verifyEmailChange", validate(verifyEmailChangeSchema) ,authController.verifyEmailChange);


/** * GET /api/auth/getSessions
 */
authRouter.get("/getSessions", authController.getSessions);


/** * DELETE /api/auth/sessions/:sessionId
 */
authRouter.delete("/sessions/:sessionId", validate(revokeSessionSchema) ,authController.revokeSession);


export default authRouter;