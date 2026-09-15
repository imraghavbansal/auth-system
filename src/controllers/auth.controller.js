import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";


export async function register(req, res) {
    const { username, email, password } = req.body;
     const isUserExist = await userModel.findOne({ 
        $or: [
            { username },
            { email }
        ]
      });

    if (isUserExist) {
        return res.status(409).json({ message: "Username or Email already exists" });
    }

    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

    const user = await userModel.create({ username, email, password: hashedPassword });
    const accessToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "7d" });
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })

    res.status(201).json({ message: "User registered successfully", 
        user:{
            username: user.username,
            email: user.email,
        },
        accessToken
    });
    
}

export async function login(req, res) {
    const token = req.headers.authorization?.split(" ")[1];
    if(!token) {
        return res.status(401).json({ message: "No token provided" });
    }
    const decoded = jwt.verify(token, config.JWT_SECRET)
    const user = await userModel.findById(decoded.id);
    res.status(200).json({
        message: "User logged in successfully",
        user: {
            username: user.username,
            email: user.email,
        }
    })
}

export async function refreshToken(req, res) {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) {
        return res.status(401).json({ message: "No refresh token provided" });
    }
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
    const user = await userModel.findById(decoded.id);
    const accessToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "15m" });

    const newRefreshToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "7d" });
    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })

    res.status(200).json({ message: "Access token refreshed successfully", accessToken });
}