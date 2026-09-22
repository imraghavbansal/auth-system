import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("mongoose", () => ({
    default: {
        connect: vi.fn()
    }
}));

vi.mock("./config.js", () => ({
    default: {
        MONGO_URI: "mongodb://test"
    }
}));

import mongoose from "mongoose";
import connectDB from "./database.js";

describe("connectDB", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("should connect to MongoDB using the configured URI", async () => {
        mongoose.connect.mockResolvedValue({});

        await connectDB();

        expect(mongoose.connect).toHaveBeenCalledWith(
            "mongodb://test"
        );
    });

    it("should reject when MongoDB connection fails", async () => {
        const error = new Error("Database connection failed");

        mongoose.connect.mockRejectedValue(error);

        await expect(connectDB()).rejects.toThrow(
            "Database connection failed"
        );
    });
});