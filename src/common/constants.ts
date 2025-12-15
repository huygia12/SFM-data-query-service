enum ResponseMessage {
    SUCCESS = "Successfull",
    BLANK_INPUT = "Input cannot be blank",
    TOKEN_INVALID = "Token is invalid",
    TOKEN_MISSING = "Missing token",
    ACCESS_DENIED = "Access denied",
    ARRAY_IS_EMPTY = "Array cannot be empty",
    PAYLOAD_IS_REQUIRED = "Payload is required",
    USER_ALREADY_EXISTS = "User already exists",
    USER_ALREADY_LOGIN = "User already login",
    USER_NOT_FOUND = "User not found",
    WRONG_PASSWORD = "Wrong password",
    RETYPE_PW_NOT_MATCH = "Retype password is not match",
    INVALID_DATA = "Please enter right data format",
    GENERATE_TOKEN_ERROR = "Generate token error",
    ADMIN_CANNOT_BE_DELETED = "Admin can't be deleted",
    UNEXPECTED_ERROR = "Unexpected Error",
    LOCKED = "Account is locked! please contact admin to unlock.",
}

enum RequestMethod {
    POST = "POST",
    PUT = "PUT",
    GET = "GET",
    DELETE = "DELETE",
    PATCH = "PATCH",
}

enum AuthToken {
    RF = "refreshToken",
    AC = "accessToken",
    OTP = "otpToken",
}

enum ImageExtension {
    JPG = "jpg",
    JPEG = "jpeg",
    PNG = "png",
    WEBP = "webp",
}

enum OCRDataType {
    OCR_WORD = "OCR_WORD",
    OCR_CHAR = "OCR_WORD",
    CHECK_BOX = "CHECK_BOX",
}

export {ResponseMessage, RequestMethod, AuthToken, ImageExtension, OCRDataType};
