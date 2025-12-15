import {Request, Response, NextFunction} from "express";
import jwtService from "../services/jwt-service";
import {OTPTokenBody, OTPType, UserInToken, UserRole} from "@/common/types";
import {AuthToken, ResponseMessage} from "@/common/constants";
import MissingTokenError from "@/errors/auth/missing-token";
import InvalidTokenError from "@/errors/auth/invalid-token";
import AccessDenided from "@/errors/auth/access-denied";

const isAuthorized = (req: Request, res: Response, next: NextFunction) => {
    const accessToken: string | string[] | undefined =
        req.headers["authorization"];

    checkAuth(accessToken, AuthToken.AC);

    console.debug(`[auth-middleware] Check authorization succeed`);
    next();
};

const isAuthorizedToAccessOTPAPI = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const otpType: number = req.body.type;

    if ([OTPType.CHANGE_PASSWORD, OTPType.UPDATE_EMAIL].includes(otpType)) {
        const accessToken: string | string[] | undefined =
            req.headers["authorization"];

        checkAuth(accessToken, AuthToken.AC);
        console.debug(`[auth-middleware] Check authorization succeed`);
    }

    next();
};

const isAuthorizedOTP = (req: Request, res: Response, next: NextFunction) => {
    const otpAuthToken: string | string[] | undefined =
        req.headers["otp-authorization"];

    checkAuth(otpAuthToken, AuthToken.OTP);

    console.debug(`[otp-auth-middleware] Check authorization succeed`);
    next();
};

const isOTPTypeisResetPw = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const otpAuthToken: string | string[] | undefined =
        req.headers["otp-authorization"];

    if (typeof otpAuthToken !== "string") {
        console.debug(
            `[auth-middleware] Check authorization failure: missing token`
        );
        throw new MissingTokenError(ResponseMessage.TOKEN_MISSING);
    }

    const otpBody = jwtService.decodeToken(
        otpAuthToken!.replace("Bearer ", "")
    ) as OTPTokenBody;

    if (otpBody.type != OTPType.CHANGE_PASSWORD) {
        console.debug(
            `[auth-middleware] Check request from right otp type has been failed: access denied`
        );
        throw new AccessDenided(ResponseMessage.ACCESS_DENIED);
    }
    console.debug(`[otp-auth-middleware] Check otp type is reset pw succeed`);
    next();
};

const isOTPTypeisChangeEmail = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const otpAuthToken: string | string[] | undefined =
        req.headers["otp-authorization"];

    if (typeof otpAuthToken !== "string") {
        console.debug(
            `[auth-middleware] Check authorization failure: missing token`
        );
        throw new MissingTokenError(ResponseMessage.TOKEN_MISSING);
    }

    const otpBody = jwtService.decodeToken(
        otpAuthToken!.replace("Bearer ", "")
    ) as OTPTokenBody;

    if (otpBody.type != OTPType.UPDATE_EMAIL) {
        console.debug(
            `[auth-middleware] Check request from right otp type has been failed: access denied`
        );
        throw new AccessDenided(ResponseMessage.ACCESS_DENIED);
    }
    console.debug(
        `[otp-auth-middleware] Check otp type is change email succeed`
    );
    next();
};

const isOTPTypeisRegister = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const otpAuthToken: string | string[] | undefined =
        req.headers["otp-authorization"];

    if (typeof otpAuthToken !== "string") {
        console.debug(
            `[auth-middleware] Check authorization failure: missing token`
        );
        throw new MissingTokenError(ResponseMessage.TOKEN_MISSING);
    }

    const otpBody = jwtService.decodeToken(
        otpAuthToken!.replace("Bearer ", "")
    ) as OTPTokenBody;

    if (otpBody.type != OTPType.REGISTER) {
        console.debug(
            `[auth-middleware] Check request from right otp type has been failed: access denied`
        );
        throw new AccessDenided(ResponseMessage.ACCESS_DENIED);
    }
    console.debug(
        `[otp-auth-middleware] Check otp type is student register succeed`
    );
    next();
};

const checkAuth = (
    token: string | undefined | string[],
    tokenType: AuthToken
) => {
    if (typeof token !== "string") {
        console.debug(
            `[auth-middleware] Check authorization failure: missing token`
        );
        throw new MissingTokenError(ResponseMessage.TOKEN_MISSING);
    }

    try {
        jwtService.verifyAuthToken(token.replace("Bearer ", ""), tokenType);
    } catch {
        console.debug(
            `[auth-middleware]: Check authorization has been failed: invalid token`
        );
        throw new InvalidTokenError(ResponseMessage.TOKEN_INVALID);
    }
};

const isAdmin = async (req: Request, res: Response, next: NextFunction) => {
    const accessToken: string | string[] | undefined =
        req.headers["authorization"];

    if (typeof accessToken !== "string") {
        console.debug(
            `[auth-middleware]: Check request from admin has been failed: missing token`
        );
        throw new MissingTokenError(ResponseMessage.TOKEN_MISSING);
    }

    const user = jwtService.decodeToken(
        accessToken.replace("Bearer ", "")
    ) as UserInToken;

    if (user.role !== UserRole.ADMIN) {
        console.debug(
            `[auth-middleware] Check request from admin has been failed: access denied`
        );
        throw new AccessDenided(ResponseMessage.ACCESS_DENIED);
    }

    console.debug(`[auth-middleware] Check request from admin succeed`);
    next();
};

export const authMiddleware = {
    isAuthorized,
    isAdmin,
    checkAuth,
    isAuthorizedOTP,
    isOTPTypeisResetPw,
    isOTPTypeisRegister,
    isOTPTypeisChangeEmail,
    isAuthorizedToAccessOTPAPI,
};
