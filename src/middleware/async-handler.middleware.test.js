import { describe, it, expect, vi } from "vitest";
import { asyncHandler } from "./async-handler.middleware.js";

describe("asyncHandler", () => {
    it("should call the wrapped function", async () => {
        const fn = vi.fn();

        const middleware = asyncHandler(fn);

        const req = {};
        const res = {};
        const next = vi.fn();

        middleware(req, res, next);

        expect(fn).toHaveBeenCalledWith(req, res, next);
    });

    it("should pass rejected errors to next", async () => {
        const error = new Error("Something went wrong");

        const fn = vi.fn().mockRejectedValue(error);

        const middleware = asyncHandler(fn);

        const req = {};
        const res = {};
        const next = vi.fn();

        middleware(req, res, next);

        await new Promise(setImmediate);

        expect(next).toHaveBeenCalledWith(error);
    });
});