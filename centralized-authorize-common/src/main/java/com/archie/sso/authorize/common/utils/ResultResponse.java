package com.archie.sso.authorize.common.utils;

import java.io.Serial;
import java.io.Serializable;

import com.archie.sso.authorize.common.enums.BusinessCodeEnum;

import lombok.Getter;

/**
 * @author lavyoung1325
 */
@Getter
public class ResultResponse<T> implements Serializable {

    @Serial
    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;

    private static final int successCode = 200;

    private static final int faultCode = 500;

    private static final int R_ERROR = 400;

    private String errorCode;

    private String errorMessage;

    private int statusCode;

    private T data;

    public ResultResponse(String errorCode, String errorMessage, int statusCode, T data) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
        this.statusCode = statusCode;
        this.data = data;
    }

    public ResultResponse() {

    }

    public ResultResponse<T> success() {
        return new ResultResponse<>("", "", successCode, null);
    }

    public ResultResponse<T> success(T data) {
        return new ResultResponse<>("", "", successCode, data);
    }

    public ResultResponse<T> fault() {
        return new ResultResponse<>(BusinessCodeEnum.SERVER_ERROR.getCode(), BusinessCodeEnum.SERVER_ERROR.getMessage(),
                faultCode, null);
    }

    public ResultResponse<T> fault(String errorCode, String errorMessage) {
        return new ResultResponse<>(errorCode, errorMessage, faultCode, null);
    }

    public ResultResponse<T> fault(int statusCode, String errorCode, String errorMessage) {
        return new ResultResponse<>(errorCode, errorMessage, statusCode, null);
    }

    public ResultResponse<T> badRequest(String errorCode, String errorMessage) {
        return new ResultResponse<>(errorCode, errorMessage, R_ERROR, null);
    }

    public ResultResponse<T> badRequest() {
        return new ResultResponse<>(BusinessCodeEnum.BAD_REQUEST.getCode(), BusinessCodeEnum.BAD_REQUEST.getMessage(),
                R_ERROR, null);
    }
}
