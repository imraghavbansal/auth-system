import { Worker } from "bullmq";

import redis from "../config/redis.js";
import { sendEmail } from "../services/email.service.js";

const emailWorker = new Worker(
    "email",
    async (job) => {
        const { to, subject, text, html } = job.data;

        await sendEmail(to, subject, text, html);

        console.log(`Email job ${job.id} completed successfully`);
    },
    {
        connection: redis
    }
);

emailWorker.on("completed", (job) => {
    console.log(`Email job ${job.id} completed`);
});

emailWorker.on("failed", (job, error) => {
    console.error(
        `Email job ${job?.id} failed on attempt ${job?.attemptsMade}:`,
        error.message
    );

    if (job && job.attemptsMade >= (job.opts.attempts ?? 1)) {
        console.error(`Email job ${job.id} permanently failed`);
    }
});

const gracefulShutdown = async (signal) => {
    console.log(`${signal} received. Starting worker shutdown...`);

    try {
        await emailWorker.close();
        console.log("Email worker closed");

        await redis.quit();
        console.log("Redis connection closed");

        console.log("Worker graceful shutdown completed");

        process.exit(0);
    } catch (error) {
        console.error("Error during worker shutdown:", error);

        process.exit(1);
    }
};

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

console.log("Email worker started");