import bcrypt from "bcrypt";
import User from "../models/User.js";
import Session from "../models/Session.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const ACCESS_TOKEN_TTL = "30m";
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 *1000; // 14 days in milliseconds

export const signUp = async (req, res) => {
    try {
        const { username, password, email, displayName } = req.body;

        if (!username || !password || !email || !displayName) {
            return res
            .status(400)
            .json({ message: "All fields are required" 

            });
        }

        //function to check if username or email already exists in the database
        const duplicate = await User.findOne({ $or: [{ username }, { email }] });
        if (duplicate) {
            return res
            .status(409)
            .json({ message: "Tên người dùng hoặc Email đã được đăng ký!" });
        }

        //function to hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // function to create new user
        await User.create({
            username,
            hashedPassword,
            email,
            displayName
        });

        //response
        return res.sendStatus(204);
    } catch (error) {
        console.error('Xuất hiện lỗi trong quá trình đăng ký:', error);
        return res.status(500).json({ message: "Đã xảy ra lỗi máy chủ. Vui lòng thử lại sau." });
    }
};

export const signIn = async (req, res) => {
    try{
        //get inputs
        const {username, password} = req.body;

        if(!username || !password){
            return res.status(400).json({message: "Tên người dùng và mật khẩu là bắt buộc!"});
        }
        // get hashed password from database
        const user = await User.findOne({username});
        if(!user){
            return res.status(401).json({message: "Tên người dùng hoặc mật khẩu không đúng!"});
        }

        // compare password with hashed password
        const passwordCorrect = await bcrypt.compare(password, user.hashedPassword);
        if(!passwordCorrect){
            return res.status(401).json({message: "Tên người dùng hoặc mật khẩu không đúng!"});
        }
        //if correct, make access token with jwt
        const accessToken = jwt.sign(
            { userId: user._id },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "15m" }
        );
        // refresh token
        const refreshToken = crypto.randomBytes(64).toString("hex");

        //make a new session to store refresh token
        await Session.create({
            userId: user._id,
            refreshToken,
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL)
        });

        //give the refresh token to client in http only cookie
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: REFRESH_TOKEN_TTL
        });

        // give access token to client in response body
        return res.status(200).json({message: `User ${user.displayName} đã log in thành công!`, accessToken});  

    }catch (error) {
        console.error('Xuất hiện lỗi trong quá trình đăng nhập:', error);
        return res.status(500).json({ message: "Đã xảy ra lỗi máy chủ. Vui lòng thử lại sau." });
    }
};

export const signOut = async (req, res) => {
    try {
        const token = req.cookies.refreshToken;

        if(token){
            await Session.deleteOne({ refreshToken: token });

            res.clearCookie("refreshToken");
        }

        return res.sendStatus(204);
    } catch (error) {
        console.error('Xuất hiện lỗi trong quá trình đăng xuất:', error);
        return res.status(500).json({ message: "Đã xảy ra lỗi máy chủ. Vui lòng thử lại sau." });
    }
};