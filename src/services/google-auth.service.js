import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";
import config from "../config/config.js";

const googleCallbackUrl =
    `${config.APP_BASE_URL}/api/auth/google/callback`;

const googleOAuthClient = new OAuth2Client(
    config.GOOGLE_AUTH_CLIENT_ID,
    config.GOOGLE_AUTH_CLIENT_SECRET,
    googleCallbackUrl
);

export const generateGoogleState = () => {
    return crypto.randomBytes(32).toString("hex");
};

export const getGoogleAuthorizationUrl = (state) => {
    return googleOAuthClient.generateAuthUrl({
        access_type: "offline",
        scope: [
            "openid",
            "email",
            "profile"
        ],
        state,
        prompt: "select_account"
    });
};

export const getGoogleUser = async (code) => {
    const { tokens } = await googleOAuthClient.getToken(code);

    if (!tokens.id_token) {
        throw new Error("Google did not return an ID token");
    }

    const ticket = await googleOAuthClient.verifyIdToken({
        idToken: tokens.id_token,
        audience: config.GOOGLE_AUTH_CLIENT_ID
    });

    const payload = ticket.getPayload();

    if (!payload) {
        throw new Error("Unable to verify Google identity");
    }

    return {
        googleId: payload.sub,
        email: payload.email?.trim().toLowerCase(),
        emailVerified: payload.email_verified === true,
        name: payload.name
    };
};