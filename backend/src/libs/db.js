import mongoose from "mongoose";

export const connectDB = async () => {
    try {
        const uri = process.env.MONGODB_CONNECTIONSTRING;

        if (!uri) {
            throw new Error("MONGODB_CONNECTIONSTRING is not defined. Check your .env file.");
        }

        await mongoose.connect(uri); 
        console.log("Connected to MongoDB");
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
        process.exit(1);
    }
};