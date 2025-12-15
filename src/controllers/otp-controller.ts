import {Request, Response} from "express";
import {StatusCodes} from "http-status-codes";
import userService from "@/services/user-service";
import otpService from "@/services/otp-service";
import mailService from "@/services/mail-service";
import {OTPCheking, OTPCreate} from "@/common/schemas";
import {ResponseMessage} from "@/common/constants";
import {
    LockStatus,
    OTPGenerationResult,
    OTPType,
    OTPValidationResult,
    StudentDTO,
} from "@/common/types";
import SendOTPFailure from "@/errors/otp/send-otp-failure";

const generateAndSendOTP = async (req: Request, res: Response) => {
    const reqBody = req.body as OTPCreate;

    let generationResult: number | undefined;
    if (reqBody.type == OTPType.REGISTER) {
        generationResult = await userService.validateStudentRegisterRequest(
            reqBody.formBody
        );
    }
    if (reqBody.type == OTPType.CHANGE_PASSWORD) {
        generationResult = await userService.validateStudentChangePwRequest(
            reqBody.email,
            reqBody.formBody
        );
    }
    if (generationResult == OTPGenerationResult.PASS) {
        const otp: string = await otpService.generateOTP(reqBody);

        try {
            mailService.sendEmail(
                reqBody.email,
                "Important information!",
                mailService.getOTPHTMLContent(otp)
            );
        } catch (error) {
            console.warn("Failed to send email: ", error);
            throw new SendOTPFailure("Fail to send OTP to:" + reqBody.email);
        }
    }

    return res.status(StatusCodes.CREATED).json({
        message: ResponseMessage.SUCCESS,
        info: {
            status: generationResult,
        },
    });
};

const checkOTP = async (req: Request, res: Response) => {
    const reqBody = req.body as OTPCheking;

    const validationResult: OTPValidationResult =
        await otpService.checkOTP(reqBody);

    let otpAuthToken: string | undefined;
    if (validationResult == OTPValidationResult.ATTEMPTS_EXCEEDED) {
        const student: StudentDTO | null =
            await userService.getStudentDTOByEmail(reqBody.email);
        if (student) {
            await userService.updateStudentLockStatus({
                studentId: student.studentId,
                status: LockStatus.LOCK,
            });
        }
    } else if (validationResult == OTPValidationResult.PASS) {
        otpAuthToken = otpService.generateOTPAuthToken(
            reqBody.email,
            reqBody.type
        );
    }

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: {
            status: validationResult,
            otpAuthToken: otpAuthToken,
        },
    });
};

export default {
    generateAndSendOTP,
    checkOTP,
};
