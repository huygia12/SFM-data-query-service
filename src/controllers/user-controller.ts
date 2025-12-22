import {NextFunction, Request, Response} from "express";
import {StatusCodes} from "http-status-codes";
import jwtService from "@/services/jwt-service";
import userService from "@/services/user-service";
import mailService from "@/services/mail-service";
import {
    AdminSignup,
    AdminLogin,
    AdminUpdate,
    StudentSignup,
    StudentLogin,
    StudentUpdate,
    StudentPwUpdate,
    StudentLockStatusUpdate,
    StudentLockChecking,
} from "@/common/schemas";
import {LockStatus, StudentDTO, UserInToken, UserRole} from "@/common/types";
import {AuthToken, ResponseMessage} from "@/common/constants";
import MissingTokenError from "@/errors/auth/missing-token";
import ms from "ms";
import UserNotFoundError from "@/errors/user/user-not-found";
import WrongPasswordError from "@/errors/user/wrong-password";
import LastPasswordRequiredError from "@/errors/user/last-password-required";
import RequestToLockedAccount from "@/errors/user/user-is-locked";
import AccessDenided from "@/errors/auth/access-denied";

/**
 * If updated email had already been existed in DB, return conflict status
 *
 * @param {Request} req
 * @param {Response} res
 */
const signupAsAdmin = async (req: Request, res: Response) => {
    const reqBody = req.body as AdminSignup;

    await userService.insertAdmin(reqBody);

    try {
        mailService.sendEmail(
            reqBody.email,
            "Welcome to Our Platform!",
            mailService.getSignUpGmailNotify()
        );
    } catch (error) {
        console.warn("Failed to send email: ", error);
    }

    return res.status(StatusCodes.CREATED).json({
        message: ResponseMessage.SUCCESS,
    });
};

/**
 * If not, create tokens and send back in header and cookie
 *
 * @param {Request} req
 * @param {Response} res
 */
const loginAsAdmin = async (req: Request, res: Response) => {
    const loginReq = req.body as AdminLogin;
    const rtInCookie = req.cookies.refreshToken as string | undefined;

    const {refreshToken, accessToken} = await userService.loginAsAdmin(
        rtInCookie,
        loginReq
    );

    //set token to cookie
    res.cookie(AuthToken.RF, refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: ms(jwtService.REFRESH_TOKEN_LIFE_SPAN),
    });

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: {
            accessToken: accessToken,
            refreshToken: refreshToken,
        },
    });
};

/**
 * Make new access token. Also checking if DB is containing this refresh token or not
 * If not, then clear all the refresh token in the DB and admin must login again for new valid refresh token
 *
 * @param {Request} req
 * @param {Response} res
 */
const refreshAdminToken = async (req: Request, res: Response) => {
    // [UPDATED] Lấy refresh token từ Body
    const {refreshToken: rtFromBody} = req.body;

    if (!rtFromBody) {
        console.debug(
            `[user controller]: refresh token: Refresh token not found in body`
        );
        throw new MissingTokenError(ResponseMessage.TOKEN_MISSING);
    }

    const tokens = await userService.refreshAdminToken(rtFromBody);

    // [DELETED] Không set cookie nữa
    // res.cookie(AuthToken.RF, tokens.refreshToken, { ... });

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken, // [ADDED] Trả về RT mới để client cập nhật
        },
    });
};

/**
 * Log admin out, clear admin's token
 * @param {Request} req
 * @param {Response} res
 * @returns
 */
const logoutAsAdmin = async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refreshToken as string;

    if (refreshToken) {
        const user = jwtService.decodeToken(refreshToken) as UserInToken;

        await userService.logoutAsAdmin(refreshToken, user.userId);
    }

    res.removeHeader("Authorization");
    res.clearCookie(AuthToken.RF);
    res.status(StatusCodes.OK).json({message: ResponseMessage.SUCCESS});
};

const deleteAdmin = async (req: Request, res: Response) => {
    const adminId = req.params.id as string;

    await userService.deleteAdmin(adminId);

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
    });
};

const getAdmin = async (req: Request, res: Response) => {
    const adminId = req.params.id as string;

    const admin = await userService.getAdminDTO(adminId);

    if (!admin) throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: admin,
    });
};

/**
 * If updated email had already been existed in DB, return conflict status
 *
 * @param {Request} req
 * @param {Response} res
 */
const updateAdminInfo = async (req: Request, res: Response) => {
    const adminId = req.params.id as string;
    const reqBody = req.body as AdminUpdate;

    if (reqBody.password !== undefined) {
        if (
            !reqBody.retypePassword ||
            reqBody.password != reqBody.retypePassword
        ) {
            throw new WrongPasswordError("Retype password is not match");
        }
        if (!reqBody.lastPassword) {
            throw new LastPasswordRequiredError(
                "Previous password is required"
            );
        }
    }

    await userService.updateAdmin(adminId, reqBody);

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
    });
};

/**
 * If updated username had already been existed in DB, return conflict status
 *
 * @param {Request} req
 * @param {Response} res
 */
const signupAsStudent = async (req: Request, res: Response) => {
    const reqBody = req.body as StudentSignup;

    await userService.insertStudents(reqBody);

    res.status(StatusCodes.CREATED).json({
        message: ResponseMessage.SUCCESS,
    });
};

/**
 * Log use in the user
 * If not, create tokens and send back in header and cookie
 *
 * @param {Request} req
 * @param {Response} res
 */
const loginAsStudent = async (req: Request, res: Response) => {
    const reqBody = req.body as StudentLogin;
    const rtInCookie = req.cookies.refreshToken as string | undefined;

    const {refreshToken, accessToken} = await userService.loginAsStudent(
        rtInCookie,
        reqBody
    );

    //set token to cookie
    res.cookie(AuthToken.RF, refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: ms(jwtService.REFRESH_TOKEN_LIFE_SPAN),
    });

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: {
            accessToken: accessToken,
            refreshToken: refreshToken,
        },
    });
};

/**
 * Log student out, clear student's token
 * @param {Request} req
 * @param {Response} res
 * @returns
 */
const logoutAsStudent = async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refreshToken as string;

    if (refreshToken) {
        const user = jwtService.decodeToken(refreshToken) as UserInToken;

        await userService.logoutAsStudent(refreshToken, user.userId);
    }

    res.removeHeader("Authorization");
    res.clearCookie(AuthToken.RF);
    res.status(StatusCodes.OK).json({message: ResponseMessage.SUCCESS});
};

/**
 * Make new access token. Also checking if DB is containing this refresh token or not
 * If not, then clear all the refresh token in the DB and user must login again for new valid refresh token
 *
 * @param {Request} req
 * @param {Response} res
 */
const refreshStudentToken = async (req: Request, res: Response) => {
    const {refreshToken: rtFromBody} = req.body;

    if (!rtFromBody) {
        throw new MissingTokenError(ResponseMessage.TOKEN_MISSING);
    }

    const {refreshToken, accessToken} =
        await userService.refreshStudentToken(rtFromBody);

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: {
            accessToken: accessToken,
            refreshToken: refreshToken,
        },
    });
};

/**
 * If
 *
 * @param {Request} req
 * @param {Response} res
 */
const updateStudentPw = async (req: Request, res: Response) => {
    const reqBody = req.body as StudentPwUpdate;

    if (reqBody.password != reqBody.retypePassword) {
        throw new WrongPasswordError(ResponseMessage.RETYPE_PW_NOT_MATCH);
    }

    await userService.updateStudentPassword(reqBody);

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
    });
};

/**
 * If updated studentCode had already been existed in DB, return conflict status
 *
 * @param {Request} req
 * @param {Response} res
 */
const updateStudentInfo = async (req: Request, res: Response) => {
    const studentId = req.params.id as string;
    const reqBody = req.body as StudentUpdate;

    await userService.updateStudent(studentId, reqBody);

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
    });
};

const getStudent = async (req: Request, res: Response) => {
    const studentId = req.params.id as string;

    const student: StudentDTO | null =
        await userService.getStudentDTO(studentId);

    if (!student) {
        throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);
    }

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: student,
    });
};

const getStudents = async (req: Request, res: Response) => {
    const students = await userService.getStudentDTOs();

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: students,
    });
};

const deleteStudent = async (req: Request, res: Response) => {
    const studentId = req.params.id as string;

    await userService.deleteStudent(studentId);

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
    });
};

const lockStudentAccount = async (req: Request, res: Response) => {
    const bodyReq = req.body as StudentLockStatusUpdate;
    const accessToken: string | string[] | undefined =
        req.headers["authorization"];

    if (typeof accessToken !== "string") {
        console.debug(
            `[user-controller]: checkStudentLockStatus: missing token`
        );
        throw new MissingTokenError(ResponseMessage.TOKEN_MISSING);
    }

    const user = jwtService.decodeToken(
        accessToken.replace("Bearer ", "")
    ) as UserInToken;

    if (user.role == UserRole.STUDENT) {
        if (
            user.userId != bodyReq.studentId ||
            bodyReq.status == LockStatus.UNLOCK
        ) {
            throw new AccessDenided(
                "Cannot lock this studentId: need permission!"
            );
        }
    }

    await userService.updateStudentLockStatus(bodyReq);

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
    });
};

const checkStudentLockStatus = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const accessToken: string | string[] | undefined =
        req.headers["authorization"];

    if (typeof accessToken == "string") {
        const user = jwtService.decodeToken(
            accessToken.replace("Bearer ", "")
        ) as UserInToken;

        if (user.role == UserRole.STUDENT) {
            const isLock: boolean = await userService.checkStudentLockStatus(
                user.userId
            );

            if (isLock) {
                console.debug(
                    `[user-controller]: checkStudentLockStatus: missing token`
                );
                throw new RequestToLockedAccount(ResponseMessage.LOCKED);
            }
        }

        console.debug(`[user-controller]: checkStudentLockStatus: pass`);
    }

    next();
};

const getStudentLockStatus = async (req: Request, res: Response) => {
    const reqBody = req.body as StudentLockChecking;

    const isLock: boolean = await userService.checkStudentLockStatus(
        reqBody.studentId
    );

    res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        status: isLock ? LockStatus.LOCK : LockStatus.UNLOCK,
    });
};

export default {
    //admins
    signupAsAdmin,
    loginAsAdmin,
    refreshAdminToken,
    logoutAsAdmin,
    deleteAdmin,
    getAdmin,
    updateAdminInfo,
    signupAsStudent,
    //students
    getStudents,
    loginAsStudent,
    refreshStudentToken,
    logoutAsStudent,
    deleteStudent,
    getStudent,
    updateStudentPw,
    updateStudentInfo,
    checkStudentLockStatus,
    lockStudentAccount,
    getStudentLockStatus,
};
