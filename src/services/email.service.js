import nodemailer from "nodemailer";
import config from "../config/config.js";
import AppError from "../utils/app-error.js";

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        type: "OAuth2",
        user: config.GOOGLE_USER,
        clientId: config.GOOGLE_CLIENT_ID,
        clientSecret: config.GOOGLE_CLIENT_SECRET,
        refreshToken: config.GOOGLE_REFRESH_TOKEN
    }
});

transporter.verify((error, success) => {
    if (error) {
        console.error("Error while connecting to email server:", error);
    } else {
        console.log("Email server connected successfully");
    }
});

export const sendEmail = async (to, subject, text, html) => {
    try {
        const info = await transporter.sendMail({
            from: `"Your Name" <${config.GOOGLE_USER}>`,
            to,
            subject,
            text,
            html
        });

        console.log("Message sent: %s", info.messageId);

        return info;
    } catch (error) {
        console.error("Error sending email:", error);

        throw new AppError(
            "Unable to send email. Please try again later.",
            503
        );
    }
};