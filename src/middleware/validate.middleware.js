export function validate(schema) {
    return (req, res, next) => {
        const result = schema.safeParse(req);
        if (!result.success) {
            return res.status(400).json({
                message: "Validation failed",
                errors: result.error.issues.map((err) => ({
                    path: err.path,
                    message: err.message,
                })),
            });
        }
        next();
    };
}