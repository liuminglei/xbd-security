package com.xbd.xbdframework.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class SignatureAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private static final long serialVersionUID = 2379975605898189295L;

    private String signature;

    public SignatureAuthenticationToken(String signature) {
        super(null, null);
        this.signature = signature;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

}
