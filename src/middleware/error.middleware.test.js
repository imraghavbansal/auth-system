import { describe, it, expect, vi } from "vitest";

import { errorHandler } from "./error.middleware.js";

describe("errorHandler", () => {
    it("should return the provided status code and error message", () => {
        const error = {
            statusCode: 401,
            message: "Authentication required"
        };

        const req = {};
        const next = vi.fn();

        const json = vi.fn();

        const res = {
            status: vi.fn().mockReturnValue({
                json
            })
        };

        errorHandler(error, req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(json).toHaveBeenCalledWith({
            message: "Authentication required"
        });
    });

    it("should return 500 when no status code is provided", () => {
        const error = {
            message: "Something went wrong"
        };

        const req = {};
        const next = vi.fn();

        const json = vi.fn();

        const res = {
            status: vi.fn().mockReturnValue({
                json
            })
        };

        errorHandler(error, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(json).toHaveBeenCalledWith({
            message: "Something went wrong"
        });
    });

    it("should return the default message when no message is provided", () => {
        const error = {
            statusCode: 500
        };

        const req = {};
        const next = vi.fn();

        const json = vi.fn();

        const res = {
            status: vi.fn().mockReturnValue({
                json
            })
        };

        errorHandler(error, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(json).toHaveBeenCalledWith({
            message: "Internal server error"
        });
    });
});