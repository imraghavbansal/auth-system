import {Router} from "express";
import * as authController from "../controllers/auth.controller.js";
const authRouter = Router();


/**
 POST /api/auth/register
 */
authRouter.post("/register", authController.register);

/** POST /api/auth/login
 */
authRouter.post("/login", authController.login);


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
authRouter.get("/verify-email", authController.verifyEmail);


/** * POST /api/auth/forgot-password
 */
authRouter.post("/forgot-password", authController.forgotPassword);


/** * POST /api/auth/reset-password
 */
authRouter.post("/reset-password", authController.resetPassword);


/** * POST /api/auth/change-password
 */
authRouter.post("/change-password", authController.changePassword);


/** * POST /api/auth/resend-otp
 */
authRouter.post("/resend-otp", authController.resendOtp);


/** * DELETE /api/auth/delete-account
 */
authRouter.delete("/delete-account", authController.deleteAccount);


/** * GET /api/auth/profile
 */
authRouter.get("/profile", authController.getProfile);


/** * PATCH /api/auth/profile
 */
authRouter.patch("/profile", authController.updateProfile);


export default authRouter;