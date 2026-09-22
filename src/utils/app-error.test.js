import { describe, it, expect } from "vitest";

import AppError from "./app-error.js";

describe("AppError", () => {
    it("should create an error with the provided message", () => {
        const error = new AppError("Something went wrong", 400);

        expect(error.message).toBe("Something went wrong");
    });

    it("should preserve the provided status code", () => {
        const error = new AppError("Unauthorized", 401);

        expect(error.statusCode).toBe(401);
    });

    it("should mark the error as operational", () => {
        const error = new AppError("Service unavailable", 503);

        expect(error.isOperational).toBe(true);
    });

    it("should be an instance of Error", () => {
        const error = new AppError("Test error", 500);

        expect(error).toBeInstanceOf(Error);
    });

    it("should be an instance of AppError", () => {
        const error = new AppError("Test error", 500);

        expect(error).toBeInstanceOf(AppError);
    });
});