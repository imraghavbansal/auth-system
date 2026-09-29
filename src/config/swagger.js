import swaggerJSDoc from "swagger-jsdoc";
import config from "./config.js";

const swaggerDefinition = {
    openapi: "3.0.3",

    info: {
        title: "Auth System API",
        version: "1.0.0",
        description:
            "Authentication and account management API for the Auth System."
    },

    servers: [
        {
            url: config.APP_BASE_URL,
            description: "API server"
        }
    ],

    tags: [
        {
            name: "Authentication",
            description: "Authentication and account lifecycle operations"
        }
    ],

    components: {
        securitySchemes: {
            bearerAuth: {
                type: "http",
                scheme: "bearer",
                bearerFormat: "JWT"
            }
        }
    }
};

const swaggerOptions = {
    definition: swaggerDefinition,

    apis: [
        "./src/routes/*.js"
    ]
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);

export default swaggerSpec;