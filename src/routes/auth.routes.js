import {Router} from "express";
import * as authController from "../controllers/auth.controller.js";
const authRouter = Router();


/**
 POST /api/auth/register
 */
authRouter.post("/register", authController.register);

/**
 GET /api/auth/login
 */
authRouter.get("/login", authController.login); 


/**
 * GET /api/auth/refresh-token
 */
authRouter.get("/refresh-token", authController.refreshToken);


export default authRouter;