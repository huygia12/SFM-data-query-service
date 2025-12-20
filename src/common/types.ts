import {Category, Field, PersonalForm} from "@prisma/client";

export enum UserRole {
    ADMIN = "ADMIN",
    STUDENT = "STUDENT",
}

export enum OTPValidationResult {
    PASS = 0,
    EXPIRED = 1,
    NOT_MATCH = 2,
    ATTEMPTS_EXCEEDED = 3,
    NOT_EXIST = 4,
}

export enum OTPGenerationResult {
    PASS = 0,
    STUDENT_CODE_EXISTED = 1,
    EMAIL_IN_USED = 2,
    STUDENT_ID_NOT_EXIST = 3,
    PW_NOT_MATCH = 4,
}

export interface StudentDTO {
    studentId: string;
    studentCode: string;
    username: string;
    email: string;
    createdAt: Date;
    deletedAt: Date | null;
}

export interface AdminDTO {
    adminId: string;
    username: string;
    email: string;
    createdAt: Date;
    deletedAt: Date | null;
}

export interface UserInToken {
    userId: string;
    username: string;
    role: UserRole;
    email: string | null;
}

export enum LockStatus {
    LOCK = 0,
    UNLOCK = 1,
}

export enum OTPType {
    REGISTER = 0,
    CHANGE_PASSWORD = 1,
    UPDATE_EMAIL = 2,
}

export interface OTPTokenBody {
    email: string;
    type: OTPType;
}

export interface Entry {
    name: string;
    value: string;
}

export type FormFullJoin = PersonalForm & {
    fields: Field[];
    category: Category;
    student: {
        studentId: string;
        studentCode: string;
        username: string;
    };
};
