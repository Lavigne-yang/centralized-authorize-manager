package com.inge.sso.authorize.common.exception;


/**
 * Created by IntelliJ IDEA.
 *
 * @author : lavyoung1325
 * @create 2023/9/24
 */
public class RegisterException extends RuntimeException {

    public RegisterException() {
    }


    public RegisterException(String message) {
        super(message);
    }
}
