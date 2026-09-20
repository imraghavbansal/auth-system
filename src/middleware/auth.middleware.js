import jwt from "jsonwebtoken";
import config from "../config/config.js";
import userModel from "../models/user.model.js";
import AppError from "../utils/app-error.js";

export async function authenticateUser(req, res, next) {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
        throw new AppError("Authentication required", 401);
    }

    const token = authorization.split(" ")[1];

    let decoded;

    try {
        decoded = jwt.verify(token, config.JWT_SECRET);
    } catch (error) {
        throw new AppError("Invalid or expired token", 401);
    }

    const user = await userModel.findById(decoded.id);

    if (!user) {
        throw new AppError("User not found", 401);
    }

    req.user = user;

    next();
}
