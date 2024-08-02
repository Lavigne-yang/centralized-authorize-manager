package com.archie.sso.authorize.common.exception;

/**
 * Created by IntelliJ IDEA.
 *
 * @author : lavyoung1325
 * @create 2023/9/28
 */
public class BusinessException extends RuntimeException{
    
    public BusinessException() {
    }
    
    public BusinessException(String message) {
        super(message);
    }
    
    public BusinessException(String message, Throwable cause) {
        super(message, cause);
    }
}
