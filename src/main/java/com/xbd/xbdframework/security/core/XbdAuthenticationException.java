package com.xbd.xbdframework.security.core;

import org.springframework.security.core.AuthenticationException;

public class XbdAuthenticationException extends AuthenticationException {

    private int code;

    private int errorCode;

    public XbdAuthenticationException(String msg) {
        super(msg);
    }

    public XbdAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

    public XbdAuthenticationException(String msg, Throwable t, int code, int errorCode) {
        super(msg, t);
        this.code = code;
        this.errorCode = errorCode;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

}
