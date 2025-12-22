import JWT from "jsonwebtoken";
import config from "@/common/app-config";
import {AuthToken} from "@/common/constants";
import {OTPTokenBody, UserInToken} from "@/common/types";

export const OTP_TOKEN_LIFE_SPAN = "2 minutes";
export const ACCESS_TOKEN_LIFE_SPAN = "5 minutes";
export const REFRESH_TOKEN_LIFE_SPAN = "7 days";

const generateToken = (
    payload: any,
    secretSignature: string,
    tokenLife: string
): string | null => {
    try {
        if (!secretSignature) {
            throw new Error("Secret token is undefined");
        }
        return JWT.sign(payload, secretSignature, {
            algorithm: "HS256",
            expiresIn: tokenLife,
        });
    } catch {
        return null;
    }
};

const verifyToken = (token: string, secretSignature: string) => {
    if (!secretSignature) {
        throw new Error("Secret token is undefined");
    }
    return JWT.verify(token, secretSignature);
};

const decodeToken = (token: string) => {
    try {
        return JWT.decode(token);
    } catch (error: any) {
        throw new Error(`Decoding token error: ${error}`);
    }
};

const generateAuthToken = (
    userInfo: UserInToken | OTPTokenBody,
    tokenType: AuthToken
): string | null => {
    const token: string | null = generateToken(
        userInfo,
        tokenType === AuthToken.AC
            ? config.AT_KEY
            : tokenType === AuthToken.RF
              ? config.RT_KEY
              : config.OTP_KEY,
        tokenType === AuthToken.AC
            ? ACCESS_TOKEN_LIFE_SPAN
            : tokenType === AuthToken.RF
              ? REFRESH_TOKEN_LIFE_SPAN
              : OTP_TOKEN_LIFE_SPAN
    );
    console.log("Generated token:", token);

    return token;
};

const verifyAuthToken = (
    token: string,
    tokenType: AuthToken
): string | JWT.JwtPayload => {
    const result = verifyToken(
        token,
        tokenType === AuthToken.AC
            ? config.AT_KEY
            : tokenType === AuthToken.RF
              ? config.RT_KEY
              : config.OTP_KEY
    );
    return result;
};

export default {
    REFRESH_TOKEN_LIFE_SPAN,
    verifyAuthToken,
    decodeToken,
    generateAuthToken,
};
