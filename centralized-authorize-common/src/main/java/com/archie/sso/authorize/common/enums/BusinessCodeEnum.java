package com.archie.sso.authorize.common.enums;

/**
 * @author lavyoung1325
 */

public enum BusinessCodeEnum {


    SUCCESS("1000", ""),
    ERROR_FAULT("1001", ""),
    BAD_REQUEST("4000", "参数错误"),
    FORBIDDEN("4001", "权限不足"),
    SERVER_ERROR("5000", "服务内部错误"),
    ;

    private final String code;

    private final String message;

    BusinessCodeEnum(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
