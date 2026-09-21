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
    console.error(`Email job ${job?.id} failed:`, error.message);
});

console.log("Email worker started");