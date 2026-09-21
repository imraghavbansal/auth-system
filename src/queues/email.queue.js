import { Queue } from "bullmq";

import redis from "../config/redis.js";

const emailQueue = new Queue("email", {
    connection: redis,
    defaultJobOptions: {
        attempts: 3,
        backoff: {
            type: "exponential",
            delay: 5000
        }
    }
});

export default emailQueue;