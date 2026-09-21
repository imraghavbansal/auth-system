import app from "./src/app.js";
import connectDB from "./src/config/database.js";
import "./src/config/redis.js";

connectDB();

app.listen(3000, () => {
    console.log("Server is running on port 3000");
})

