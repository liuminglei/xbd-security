package com.xbd.xbdframework.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class UsernameAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private static final long serialVersionUID = 2712122198404965350L;

    public UsernameAuthenticationToken(Object principal) {
        super(principal, null);
    }

}
