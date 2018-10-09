package com.xbd.xbdframework.security.core.userdetails;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface SignatureUserDetailsService {

    UserDetails loadUserBySignature(String signature) throws UsernameNotFoundException;

}
