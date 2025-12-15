import {compareSync, hashSync} from "bcrypt";
import {
    AdminSignup,
    AdminLogin,
    AdminUpdate,
    StudentSignup,
    StudentLogin,
    StudentUpdate,
    StudentPwUpdate,
    StudentLockStatusUpdate,
} from "@/common/schemas";
import prisma from "@/common/prisma-client";
import {
    AdminDTO,
    LockStatus,
    OTPGenerationResult,
    StudentDTO,
    UserInToken,
    UserRole,
} from "@/common/types";
import UserAlreadyExistError from "@/errors/user/user-already-exist";
import {AuthToken, ResponseMessage} from "@/common/constants";
import UserNotFoundError from "@/errors/user/user-not-found";
import WrongPasswordError from "@/errors/user/wrong-password";
import jwtService from "./jwt-service";
import InvalidTokenError from "@/errors/auth/invalid-token";
import {Admin, Student} from "@prisma/client";
import RequestToLockedAccount from "@/errors/user/user-is-locked";

const saltOfRound = 10;

//admins
const updateAdmin = async (
    adminId: string,
    validPayload: AdminUpdate
): Promise<void> => {
    if (validPayload.email) {
        const duplicatedAdminAccount = await getAdminByEmail(
            validPayload.email
        );

        if (
            duplicatedAdminAccount &&
            duplicatedAdminAccount.adminId !== adminId
        )
            throw new UserAlreadyExistError(
                ResponseMessage.USER_ALREADY_EXISTS
            );
    }
    if (validPayload.password && validPayload.lastPassword) {
        const match = checkAdminPasswordMatch(
            adminId,
            validPayload.lastPassword
        );
        if (!match)
            throw new WrongPasswordError(ResponseMessage.WRONG_PASSWORD);
    }

    await prisma.admin.update({
        where: {
            adminId: adminId,
        },
        data: {
            email: validPayload.email,
            username: validPayload.username,
            password:
                validPayload.password &&
                hashSync(validPayload.password, saltOfRound),
        },
    });
};

const checkAdminPasswordMatch = async (
    adminId: string,
    password: string
): Promise<boolean> => {
    const adminAccount = await getAdminById(adminId);

    if (!adminAccount)
        throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);

    // Check whether password is valid
    return compareSync(password, adminAccount.password);
};

const logoutAsAdmin = async (token: string, userId: string) => {
    await deleteAdminRefreshToken(token, userId);
};

const clearAdminRefreshTokens = async (adminId: string) => {
    await prisma.admin.update({
        where: {adminId: adminId},
        data: {
            refreshTokens: [],
        },
    });
};

const deleteAdminRefreshToken = async (
    refreshToken: string,
    adminId: string
) => {
    const newRefreshTokens: string[] = await prisma.admin
        .findFirst({where: {adminId: adminId}})
        .then((user) => {
            if (!user) {
                throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);
            }
            return user.refreshTokens.filter((token) => token !== refreshToken);
        });

    await prisma.admin.update({
        where: {
            adminId: adminId,
        },
        data: {
            refreshTokens: newRefreshTokens,
        },
    });
};

const checkIfAdminRefreshTokenExistInDB = async (
    refreshToken: string,
    adminId: string
): Promise<boolean> => {
    const counter = await prisma.admin.count({
        where: {
            adminId: adminId,
            deletedAt: null,
            refreshTokens: {has: refreshToken},
        },
    });

    return counter > 0;
};

const pushAdminRefreshToken = async (refreshToken: string, adminId: string) => {
    await prisma.admin.update({
        where: {
            adminId: adminId,
        },
        data: {
            refreshTokens: {
                push: refreshToken,
            },
        },
    });
};

const getAdminById = async (adminId: string): Promise<Admin | null> => {
    const user = await prisma.admin.findFirst({
        where: {
            adminId: adminId,
        },
    });

    return user;
};

const getAdminByEmail = async (email: string): Promise<Admin | null> => {
    const user = await prisma.admin.findFirst({
        where: {
            email: email,
        },
    });

    return user;
};

const getAdminDTO = async (adminId: string): Promise<AdminDTO | null> => {
    const admin = await prisma.admin.findUnique({
        where: {
            adminId: adminId,
        },
        select: {
            adminId: true,
            email: true,
            username: true,
            createdAt: true,
            deletedAt: true,
        },
    });

    return admin;
};

const getValidAdmin = async (
    email: string,
    password: string
): Promise<Admin> => {
    const findByEmail = await getAdminByEmail(email);

    if (!findByEmail)
        throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);

    // Check whether password is valid
    const match = compareSync(password, findByEmail.password);
    if (!match) throw new WrongPasswordError(ResponseMessage.WRONG_PASSWORD);

    return findByEmail;
};

const insertAdmin = async (validPayload: AdminSignup): Promise<void> => {
    const duplicatedAdminAccount = await getAdminByEmail(validPayload.email);

    if (duplicatedAdminAccount)
        throw new UserAlreadyExistError(ResponseMessage.USER_ALREADY_EXISTS);

    await prisma.admin.create({
        data: {
            username: validPayload.username,
            password: hashSync(validPayload.password, saltOfRound),
            email: validPayload.email,
        },
    });
};

const loginAsAdmin = async (
    prevRT: string | undefined,
    validPayload: AdminLogin
): Promise<{refreshToken: string; accessToken: string}> => {
    try {
        if (typeof prevRT == "string") {
            // Get userId from refreshtoken payload
            const userDecoded = jwtService.decodeToken(prevRT) as UserInToken;

            // If refresh token already existed in DB so delete it
            await deleteAdminRefreshToken(prevRT, userDecoded.userId);
        }
    } catch (error: any) {
        console.debug(`[user service]: login : ${JSON.stringify(error)}`);
    }

    const validAdmin: Admin = await getValidAdmin(
        validPayload.email,
        validPayload.password
    );

    const payload: UserInToken = {
        userId: validAdmin.adminId,
        username: validAdmin.username,
        role: UserRole.ADMIN,
        email: null,
    };

    //create AT, RT
    const accessToken: string | null = jwtService.generateAuthToken(
        payload,
        AuthToken.AC
    );

    const refreshToken: string | null = jwtService.generateAuthToken(
        payload,
        AuthToken.RF
    );

    if (!accessToken || !refreshToken)
        throw new Error(ResponseMessage.GENERATE_TOKEN_ERROR);

    //Push refresh token to DB
    await pushAdminRefreshToken(refreshToken, validAdmin.adminId);
    return {refreshToken, accessToken};
};

const refreshAdminToken = async (
    prevRT: string
): Promise<{accessToken: string; refreshToken: string}> => {
    try {
        const userDecoded = jwtService.verifyAuthToken(
            prevRT,
            AuthToken.RF
        ) as UserInToken;

        //Hacker's request: must clear all refresh token to login again
        const existing: boolean = await checkIfAdminRefreshTokenExistInDB(
            prevRT,
            userDecoded.userId
        );

        if (!existing) {
            console.debug(
                `[user service]: refresh token: unknown refresh token`
            );
            await clearAdminRefreshTokens(userDecoded.userId);
            throw new InvalidTokenError(ResponseMessage.TOKEN_INVALID);
        }

        //Down here token must be valid
        const adminDTO = await getAdminDTO(userDecoded.userId);

        if (!adminDTO)
            throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);

        await deleteAdminRefreshToken(prevRT, userDecoded.userId);
        const payload: UserInToken = {
            userId: adminDTO.adminId,
            username: adminDTO.username,
            role: UserRole.ADMIN,
            email: null,
        };

        //create AT, RT
        const accessToken: string | null = jwtService.generateAuthToken(
            payload,
            AuthToken.AC
        );

        const refreshToken: string | null = jwtService.generateAuthToken(
            payload,
            AuthToken.RF
        );

        if (!accessToken || !refreshToken)
            throw new Error(ResponseMessage.GENERATE_TOKEN_ERROR);

        //Push refresh token to DB
        await pushAdminRefreshToken(refreshToken, adminDTO.adminId);
        return {accessToken, refreshToken};
    } catch {
        throw new InvalidTokenError(ResponseMessage.TOKEN_INVALID);
    }
};

const deleteAdmin = async (adminId: string) => {
    const admin = await getAdminDTO(adminId);

    if (!admin) throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);

    await prisma.admin.update({
        where: {
            adminId: adminId,
        },
        data: {
            deletedAt: new Date(),
        },
    });
};

// ------------------------------------ students ------------------------------------
const checkUserPasswordMatch = async (
    studentId: string,
    password: string
): Promise<boolean> => {
    const adminAccount = await getStudentById(studentId);

    if (!adminAccount)
        throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);

    // Check whether password is valid
    return compareSync(password, adminAccount.password);
};

const checkIfStudentRefreshTokenExistInDB = async (
    refreshToken: string,
    adminId: string
): Promise<boolean> => {
    const counter = await prisma.student.count({
        where: {
            studentId: adminId,
            deletedAt: null,
            refreshTokens: {has: refreshToken},
        },
    });

    return counter > 0;
};

const clearStudentRefreshTokens = async (studentId: string) => {
    await prisma.student.update({
        where: {studentId: studentId},
        data: {
            refreshTokens: [],
        },
    });
};

const refreshStudentToken = async (
    prevRT: string
): Promise<{accessToken: string; refreshToken: string}> => {
    try {
        const userDecoded = jwtService.verifyAuthToken(
            prevRT,
            AuthToken.RF
        ) as UserInToken;

        //Hacker's request: must clear all refresh token to login again
        const existing: boolean = await checkIfStudentRefreshTokenExistInDB(
            prevRT,
            userDecoded.userId
        );

        if (!existing) {
            console.debug(
                `[user service]: refresh token: unknown refresh token`
            );
            await clearStudentRefreshTokens(userDecoded.userId);
            throw new InvalidTokenError(ResponseMessage.TOKEN_INVALID);
        }

        //Down here token must be valid
        const userDTO = await getStudentDTO(userDecoded.userId);

        if (!userDTO)
            throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);

        await deleteStudentRefreshToken(prevRT, userDecoded.userId);
        const payload: UserInToken = {
            userId: userDTO.studentId,
            username: userDTO.username,
            role: UserRole.STUDENT,
            email: userDTO.email,
        };

        //create AT, RT
        const accessToken: string | null = jwtService.generateAuthToken(
            payload,
            AuthToken.AC
        );

        const refreshToken: string | null = jwtService.generateAuthToken(
            payload,
            AuthToken.RF
        );

        if (!accessToken || !refreshToken)
            throw new Error(ResponseMessage.GENERATE_TOKEN_ERROR);

        //Push refresh token to DB
        await pushStudentRefreshToken(refreshToken, userDTO.studentId);
        return {accessToken, refreshToken};
    } catch {
        throw new InvalidTokenError(ResponseMessage.TOKEN_INVALID);
    }
};

const logoutAsStudent = async (token: string, studentId: string) => {
    await deleteStudentRefreshToken(token, studentId);
};

const pushStudentRefreshToken = async (
    refreshToken: string,
    studentId: string
) => {
    await prisma.student.update({
        where: {
            studentId: studentId,
        },
        data: {
            refreshTokens: {
                push: refreshToken,
            },
        },
    });
};

const deleteStudentRefreshToken = async (
    refreshToken: string,
    studentId: string
) => {
    const newRefreshTokens: string[] = await prisma.student
        .findFirst({where: {studentId: studentId}})
        .then((user) => {
            if (!user) {
                throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);
            }
            return user.refreshTokens.filter((token) => token !== refreshToken);
        });

    await prisma.student.update({
        where: {
            studentId: studentId,
        },
        data: {
            refreshTokens: newRefreshTokens,
        },
    });
};

const getStudentDTO = async (studentId: string): Promise<StudentDTO | null> => {
    const student = await prisma.student.findUnique({
        where: {
            studentId: studentId,
        },
        select: {
            studentId: true,
            studentCode: true,
            email: true,
            username: true,
            createdAt: true,
            deletedAt: true,
        },
    });

    return student;
};

const getStudentDTOByEmail = async (
    email: string
): Promise<StudentDTO | null> => {
    const student = await prisma.student.findUnique({
        where: {
            email: email,
        },
        select: {
            studentId: true,
            studentCode: true,
            email: true,
            username: true,
            createdAt: true,
            deletedAt: true,
        },
    });

    return student;
};

const insertStudents = async (validPayload: StudentSignup): Promise<void> => {
    const duplicatedStudentCode = await getStudentByStudentCode(
        validPayload.studentCode
    );

    if (duplicatedStudentCode)
        throw new UserAlreadyExistError(ResponseMessage.USER_ALREADY_EXISTS);

    await prisma.student.createMany({
        data: {
            ...validPayload,
            password: hashSync(validPayload.password, saltOfRound),
        },
    });
};

const getStudentDTOs = async (
    limit: number = 10,
    deletedInclude: boolean = false,
    currentPage: number = 1
): Promise<StudentDTO[]> => {
    const students = await prisma.student.findMany({
        where: {
            deletedAt: deletedInclude ? undefined : null,
        },
        select: {
            studentId: true,
            studentCode: true,
            username: true,
            gender: true,
            birthPlace: true,
            phoneNumber: true,
            email: true,
            class: true,
            createdAt: true,
            deletedAt: true,
        },
        skip: (currentPage - 1) * limit,
        take: limit,
    });

    return students;
};

const getStudentByStudentCode = async (
    studentCode: string
): Promise<Student | null> => {
    const student = await prisma.student.findFirst({
        where: {
            studentCode: studentCode,
        },
    });

    return student;
};

const getStudentById = async (studentId: string): Promise<Student | null> => {
    const user = await prisma.student.findFirst({
        where: {
            studentId: studentId,
        },
    });

    return user;
};

const getStudentDTOByStudentCode = async (
    studentCode: string
): Promise<StudentDTO | null> => {
    const student = await prisma.student.findFirst({
        where: {
            studentCode: studentCode,
        },
        select: {
            studentId: true,
            studentCode: true,
            username: true,
            email: true,
            gender: true,
            birthPlace: true,
            phoneNumber: true,
            class: true,
            createdAt: true,
            deletedAt: true,
        },
    });

    return student;
};

const getValidStudent = async (
    email: string,
    password: string
): Promise<Student> => {
    const findByStudentCode = await getStudentByStudentCode(email);

    if (!findByStudentCode)
        throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);

    if (findByStudentCode.lockStatus == true)
        throw new RequestToLockedAccount(ResponseMessage.LOCKED);

    // Check whether password is valid
    const match = compareSync(password, findByStudentCode.password);
    if (!match) throw new WrongPasswordError(ResponseMessage.WRONG_PASSWORD);

    return findByStudentCode;
};

const loginAsStudent = async (
    prevRT: string | undefined,
    validPayload: StudentLogin
): Promise<{refreshToken: string; accessToken: string}> => {
    try {
        if (typeof prevRT == "string") {
            // Get userId from refreshtoken payload
            const userDecoded = jwtService.decodeToken(prevRT) as UserInToken;

            // If refresh token already existed in DB so delete it
            await deleteStudentRefreshToken(prevRT, userDecoded.userId);
        }
    } catch (error: any) {
        console.debug(`[user service]: login : ${JSON.stringify(error)}`);
    }

    const validStudent: Student = await getValidStudent(
        validPayload.studentCode,
        validPayload.password
    );

    const payload: UserInToken = {
        userId: validStudent.studentId,
        username: validStudent.username,
        role: UserRole.STUDENT,
        email: validStudent.email,
    };

    //create AT, RT
    const accessToken: string | null = jwtService.generateAuthToken(
        payload,
        AuthToken.AC
    );

    const refreshToken: string | null = jwtService.generateAuthToken(
        payload,
        AuthToken.RF
    );

    if (!accessToken || !refreshToken)
        throw new Error(ResponseMessage.GENERATE_TOKEN_ERROR);

    //Push refresh token to DB
    await pushStudentRefreshToken(refreshToken, validStudent.studentId);
    return {refreshToken, accessToken};
};

const deleteStudent = async (studentId: string) => {
    const student = await getStudentDTO(studentId);

    if (!student) throw new UserNotFoundError(ResponseMessage.USER_NOT_FOUND);

    await prisma.student.update({
        where: {
            studentId: studentId,
        },
        data: {
            deletedAt: new Date(),
        },
    });
};

const updateStudent = async (
    studentId: string,
    validPayload: StudentUpdate
): Promise<void> => {
    if (validPayload.studentCode) {
        const duplicatedStudentAccount = await getStudentByStudentCode(
            validPayload.studentCode
        );

        if (
            duplicatedStudentAccount &&
            duplicatedStudentAccount.studentId !== studentId
        )
            throw new UserAlreadyExistError(
                ResponseMessage.USER_ALREADY_EXISTS
            );
    }

    await prisma.student.update({
        where: {
            studentId: studentId,
        },
        data: {
            studentCode: validPayload.studentCode,
            username: validPayload.username,
            gender: validPayload.gender,
            birthPlace: validPayload.birthPlace,
            phoneNumber: validPayload.phoneNumber,
            class: validPayload.class,
        },
    });
};

const updateStudentLockStatus = async (
    validPayload: StudentLockStatusUpdate
): Promise<void> => {
    await prisma.student.update({
        where: {
            studentId: validPayload.studentId,
        },
        data: {
            lockStatus: validPayload.status == LockStatus.LOCK,
        },
    });
};

const updateStudentPassword = async (
    validPayload: StudentPwUpdate
): Promise<void> => {
    await prisma.student.update({
        where: {
            studentId: validPayload.studentId,
        },
        data: {
            password:
                validPayload.password &&
                hashSync(validPayload.password, saltOfRound),
        },
    });
};

const validateStudentRegisterRequest = async (
    data: StudentSignup
): Promise<OTPGenerationResult> => {
    const duplicatedStudentAccount: Student | null =
        await prisma.student.findFirst({
            where: {
                OR: [
                    {
                        studentCode: data.studentCode,
                    },
                    {
                        email: data.email,
                    },
                ],
            },
        });

    if (duplicatedStudentAccount != null) {
        if (duplicatedStudentAccount.email == data.email) {
            return OTPGenerationResult.EMAIL_IN_USED;
        }
        if (duplicatedStudentAccount.studentCode == data.studentCode) {
            return OTPGenerationResult.STUDENT_CODE_EXISTED;
        }
    }

    return OTPGenerationResult.PASS;
};

const validateStudentChangePwRequest = async (
    email: string,
    data: StudentPwUpdate
): Promise<OTPGenerationResult> => {
    const duplicatedStudentAccount: Student | null =
        await prisma.student.findFirst({
            where: {
                studentId: data.studentId,
                email: email,
            },
        });

    if (duplicatedStudentAccount == null) {
        return OTPGenerationResult.STUDENT_ID_NOT_EXIST;
    } else {
        const match = await checkUserPasswordMatch(
            data.studentId,
            data.lastPassword
        );
        if (!match) return OTPGenerationResult.PW_NOT_MATCH;
    }

    return OTPGenerationResult.PASS;
};

const checkStudentLockStatus = async (studentId: string): Promise<boolean> => {
    const student = await prisma.student.findFirst({
        where: {
            studentId: studentId,
        },
        select: {
            lockStatus: true,
        },
    });

    return student != null && student.lockStatus == true;
};

export default {
    // admin
    insertAdmin,
    loginAsAdmin,
    refreshAdminToken,
    logoutAsAdmin,
    deleteAdmin,
    getAdminDTO,
    updateAdmin,
    insertStudents,
    // student
    getStudentDTOs,
    loginAsStudent,
    refreshStudentToken,
    logoutAsStudent,
    deleteStudent,
    getStudentDTO,
    getStudentDTOByEmail,
    getStudentDTOByStudentCode,
    updateStudent,
    updateStudentPassword,
    checkUserPasswordMatch,
    checkStudentLockStatus,
    updateStudentLockStatus,
    validateStudentRegisterRequest,
    validateStudentChangePwRequest,
};
