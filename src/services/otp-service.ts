import {compareSync, hashSync} from "bcrypt";
import prisma from "@/common/prisma-client";
import * as crypto from "crypto";
import jwtService from "./jwt-service";
import {OTPTokenBody, OTPType, OTPValidationResult} from "@/common/types";
import {AuthToken, ResponseMessage} from "@/common/constants";
import {OTPCheking, OTPCreate} from "@/common/schemas";

const saltOfRound = 10;
const defaultValidateAttempts = 5;
const defaultOTPTimeSpan = 1;

const insertOTP = async (
    email: string,
    type: OTPType,
    otp: string
): Promise<void> => {
    const now = new Date();

    const existedStudentOTP = await prisma.oTP.findFirst({
        where: {
            email: email,
            type: type,
        },
    });

    if (!existedStudentOTP) {
        await prisma.oTP.create({
            data: {
                email: email,
                type: type,
                otpHash: hashSync(otp, saltOfRound),
                expireAt: new Date(
                    now.getTime() + defaultOTPTimeSpan * 60 * 1000
                ),
                validateAttempts: defaultValidateAttempts,
                createdAt: new Date(),
            },
        });
    } else {
        await prisma.oTP.updateMany({
            where: {
                email: email,
                type: type,
            },
            data: {
                otpHash: hashSync(otp, saltOfRound),
                expireAt: new Date(
                    now.getTime() + defaultOTPTimeSpan * 60 * 1000
                ),
                validateAttempts: defaultValidateAttempts,
                createdAt: new Date(),
            },
        });
    }
};

const generateOTP = async (validBody: OTPCreate): Promise<string> => {
    const otp = crypto.randomInt(100000, 999999).toString();

    await insertOTP(validBody.email, validBody.type, otp);

    return otp;
};

const checkOTP = async (validBody: OTPCheking): Promise<number> => {
    const otp = await prisma.oTP.findFirst({
        where: {
            email: validBody.email,
            type: validBody.type,
        },
    });

    if (!otp || !otp.otpHash || !otp.expireAt) {
        //tra ve loi
        return OTPValidationResult.NOT_EXIST;
    }

    if (otp.validateAttempts <= 0) {
        return OTPValidationResult.ATTEMPTS_EXCEEDED;
    }

    if (otp.expireAt < new Date()) {
        return OTPValidationResult.EXPIRED;
    }

    if (!compareSync(validBody.otp, otp.otpHash)) {
        //tra ve true
        await prisma.oTP.update({
            where: {
                Id: otp.Id,
            },
            data: {
                validateAttempts: otp.validateAttempts - 1,
            },
        });
        return OTPValidationResult.NOT_MATCH;
    }
    return OTPValidationResult.PASS;
};

const generateOTPAuthToken = (email: string, type: OTPType): string => {
    const otpTokenBody: OTPTokenBody = {
        email: email,
        type: type,
    };

    const otpToken: string | null = jwtService.generateAuthToken(
        otpTokenBody,
        AuthToken.OTP
    );

    if (!otpToken) {
        throw new Error(ResponseMessage.GENERATE_TOKEN_ERROR);
    }

    return otpToken;
};

export default {
    generateOTP,
    generateOTPAuthToken,
    checkOTP,
};
