import express from "express";
import morgan from "morgan";
import authRouter from "./routes/auth.routes.js";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";

import redis from "./config/redis.js";

import swaggerUi from "swagger-ui-express";
import swaggerSpec from "./config/swagger.js";

import { errorHandler } from "./middleware/error.middleware.js";

const app = express();

app.use(express.json());

app.use(morgan("dev"));

app.use(cookieParser());

app.get("/health", async (req, res) => {
    const mongoHealthy = mongoose.connection.readyState === 1;

    let redisHealthy = false;

    if (redis.status === "ready") {
        try {
            const redisPing = redis.ping();

            const timeout = new Promise((_, reject) => {
                setTimeout(() => {
                    reject(new Error("Redis health check timed out"));
                }, 1000);
            });

            redisHealthy = (await Promise.race([
                redisPing,
                timeout
            ])) === "PONG";
        } catch (error) {
            redisHealthy = false;
        }
    }

    const healthy = mongoHealthy && redisHealthy;

    res.status(healthy ? 200 : 503).json({
        status: healthy ? "ok" : "unhealthy",
        database: mongoHealthy ? "connected" : "disconnected",
        redis: redisHealthy ? "connected" : "disconnected"
    });
});

app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(swaggerSpec)
);

app.use("/api/auth", authRouter);

app.use(errorHandler);

export default app;