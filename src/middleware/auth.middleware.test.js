import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("jsonwebtoken", () => ({
    default: {
        verify: vi.fn()
    }
}));

vi.mock("../models/user.model.js", () => ({
    default: {
        findById: vi.fn()
    }
}));

import jwt from "jsonwebtoken";
import userModel from "../models/user.model.js";
import { authenticateUser } from "./auth.middleware.js";

describe("authenticateUser", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("should reject when authorization header is missing", async () => {
        const req = {
            headers: {}
        };

        const res = {};
        const next = vi.fn();

        await expect(
            authenticateUser(req, res, next)
        ).rejects.toMatchObject({
            message: "Authentication required",
            statusCode: 401
        });

        expect(next).not.toHaveBeenCalled();
    });

    it("should reject when authorization header is invalid", async () => {
        const req = {
            headers: {
                authorization: "Basic abc123"
            }
        };

        const res = {};
        const next = vi.fn();

        await expect(
            authenticateUser(req, res, next)
        ).rejects.toMatchObject({
            message: "Authentication required",
            statusCode: 401
        });

        expect(next).not.toHaveBeenCalled();
    });

    it("should reject when JWT is invalid or expired", async () => {
        const req = {
            headers: {
                authorization: "Bearer invalid-token"
            }
        };

        const res = {};
        const next = vi.fn();

        jwt.verify.mockImplementation(() => {
            throw new Error("Invalid token");
        });

        await expect(
            authenticateUser(req, res, next)
        ).rejects.toMatchObject({
            message: "Invalid or expired token",
            statusCode: 401
        });

        expect(userModel.findById).not.toHaveBeenCalled();
        expect(next).not.toHaveBeenCalled();
    });

    it("should reject when authenticated user does not exist", async () => {
        const req = {
            headers: {
                authorization: "Bearer valid-token"
            }
        };

        const res = {};
        const next = vi.fn();

        jwt.verify.mockReturnValue({
            id: "user123"
        });

        userModel.findById.mockResolvedValue(null);

        await expect(
            authenticateUser(req, res, next)
        ).rejects.toMatchObject({
            message: "User not found",
            statusCode: 401
        });

        expect(userModel.findById).toHaveBeenCalledWith("user123");
        expect(next).not.toHaveBeenCalled();
    });

    it("should attach user to request and call next when authentication succeeds", async () => {
        const req = {
            headers: {
                authorization: "Bearer valid-token"
            }
        };

        const res = {};
        const next = vi.fn();

        const user = {
            _id: "user123",
            username: "raghav"
        };

        jwt.verify.mockReturnValue({
            id: "user123"
        });

        userModel.findById.mockResolvedValue(user);

        await authenticateUser(req, res, next);

        expect(userModel.findById).toHaveBeenCalledWith("user123");
        expect(req.user).toBe(user);
        expect(next).toHaveBeenCalledTimes(1);
    });
});