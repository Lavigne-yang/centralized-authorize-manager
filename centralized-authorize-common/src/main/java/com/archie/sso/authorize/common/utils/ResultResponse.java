package com.archie.sso.authorize.common.utils;

import com.archie.sso.authorize.common.constants.ResultCodeConstant;

import java.io.Serial;
import java.io.Serializable;

/**
 * @author lavyoung1325
 */
public class ResultResponse<T> implements Serializable {
    
    @Serial
    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;
    
    private int code;
    
    private String message;
    
    private T data;
    
    
    public ResultResponse() {
    
    }
    
    public ResultResponse(int code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }
    
    public ResultResponse<T> success() {
        return new ResultResponse<>(ResultCodeConstant.SUCCESS.getCode(), "", null);
    }
    
    public ResultResponse<T> success(T data) {
        return new ResultResponse<>(ResultCodeConstant.SUCCESS.getCode(), "", data);
    }
    
    public ResultResponse<T> fault(ResultCodeConstant resultCode, String message) {
        return new ResultResponse<>(resultCode.getCode(), message, null);
    }
    
    public ResultResponse<T> fault(ResultCodeConstant resultCode, String message, T data) {
        return new ResultResponse<>(resultCode.getCode(), message, data);
    }
    
    public ResultResponse<T> body(T data) {
        this.data = data;
        return this;
    }
}
