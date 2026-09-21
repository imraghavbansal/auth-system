import app from "./src/app.js";
import connectDB from "./src/config/database.js";
import mongoose from "mongoose";
import redis from "./src/config/redis.js";

const PORT = 3000;

connectDB();

const server = app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

const gracefulShutdown = async (signal) => {
    console.log(`${signal} received. Starting graceful shutdown...`);

    try {
        await new Promise((resolve, reject) => {
            server.close((error) => {
                if (error) {
                    reject(error);
                } else {
                    resolve();
                }
            });
        });

        console.log("HTTP server closed");

        await mongoose.connection.close();
        console.log("MongoDB connection closed");

        await redis.quit();
        console.log("Redis connection closed");

        console.log("Graceful shutdown completed");

        process.exit(0);
    } catch (error) {
        console.error("Error during graceful shutdown:", error);

        process.exit(1);
    }
};

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));