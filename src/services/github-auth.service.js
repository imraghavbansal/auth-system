import crypto from "crypto";
import config from "../config/config.js";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL = "https://api.github.com/user";
const GITHUB_EMAILS_URL = "https://api.github.com/user/emails";

export const generateGithubState = () => {
    return crypto.randomBytes(32).toString("hex");
};

export const getGithubAuthorizationUrl = (state) => {
    const params = new URLSearchParams({
        client_id: config.GITHUB_CLIENT_ID,
        redirect_uri: `${config.APP_BASE_URL}/api/auth/github/callback`,
        scope: "read:user user:email",
        state
    });

    return `${GITHUB_AUTHORIZE_URL}?${params.toString()}`;
};

export const exchangeGithubCode = async (code) => {
    const response = await fetch(GITHUB_TOKEN_URL, {
        method: "POST",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            client_id: config.GITHUB_CLIENT_ID,
            client_secret: config.GITHUB_CLIENT_SECRET,
            code
        })
    });

    if (!response.ok) {
        throw new Error("Failed to exchange GitHub authorization code");
    }

    const data = await response.json();

    if (!data.access_token) {
        throw new Error("GitHub access token was not returned");
    }

    return data.access_token;
};

export const getGithubUser = async (accessToken) => {
    const response = await fetch(GITHUB_USER_URL, {
        headers: {
            Accept: "application/vnd.github+json",
            Authorization: `Bearer ${accessToken}`,
            "X-GitHub-Api-Version": "2022-11-28"
        }
    });

    if (!response.ok) {
        throw new Error("Failed to fetch GitHub user");
    }

    return response.json();
};

export const getGithubPrimaryEmail = async (accessToken) => {
    const response = await fetch(GITHUB_EMAILS_URL, {
        headers: {
            Accept: "application/vnd.github+json",
            Authorization: `Bearer ${accessToken}`,
            "X-GitHub-Api-Version": "2022-11-28"
        }
    });

    if (!response.ok) {
        throw new Error("Failed to fetch GitHub email");
    }

    const emails = await response.json();

    const primaryEmail = emails.find(
        (email) => email.primary && email.verified
    );

    return primaryEmail?.email?.toLowerCase() ?? null;
};