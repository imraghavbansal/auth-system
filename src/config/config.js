import dotenv from "dotenv";
dotenv.config();               //isko call kre bina .env ke jitne vairbales create hue h wo kaam nhi krenge

if(!process.env.MONGO_URI){
    throw new Error("MONGO_URI is not defined in .env file");
}

if(!process.env.JWT_SECRET){
    throw new Error("JWT_SECRET is not defined in .env file");
}

const config = {
    MONGO_URI: process.env.MONGO_URI,
    JWT_SECRET: process.env.JWT_SECRET
}
export default config;