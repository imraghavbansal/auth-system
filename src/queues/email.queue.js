import { Queue } from "bullmq";
import redis from "../config/redis.js";

const emailQueue = new Queue("email", {
    connection: redis
});

export default emailQueue;