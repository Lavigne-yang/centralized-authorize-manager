package com.archie.sso.authorize.common.constants;

/**
 * @author lavyoung1325
 */

public enum ResultCodeConstant {
    
    
    SUCCESS(200),
    
    ERROR_FAULT(500),
    ;
    
    private final int code;
    
    ResultCodeConstant(int code) {
        this.code = code;
    }
    
    
    public int getCode() {
        return code;
    }
    
}
