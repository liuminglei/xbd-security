package com.xbd.xbdframework.security.core.userdetails;

import com.xbd.xbdframework.security.service.UserLoaderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class XbdSignatureUserDetailsService implements SignatureUserDetailsService {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private UserLoaderService userLoaderService;

    @Override
    public UserDetails loadUserBySignature(String signature) throws UsernameNotFoundException {
        UserDetails userDetails = this.userLoaderService.getUserBySignature(signature);

        if (logger.isDebugEnabled()) {
            logger.debug("登录用户信息：{}", new Object[] { userDetails.toString() });
        }

        return userDetails;
    }

}
