package com.xbd.xbdframework.security.core.userdetails;

import com.xbd.xbdframework.security.service.UserLoaderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class XbdUserDetailsService implements UserDetailsService {
    private Logger logger = LoggerFactory.getLogger(getClass());

    private UserLoaderService userLoaderService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails userDetails = this.userLoaderService.getUserByUsername(username);

        if (logger.isDebugEnabled()) {
            logger.debug("登录用户信息：{}", new Object[] { userDetails.toString() });
        }

        return userDetails;
    }

    public UserLoaderService getUserLoaderService() {
        return userLoaderService;
    }

    public void setUserLoaderService(UserLoaderService userLoaderService) {
        this.userLoaderService = userLoaderService;
    }
}
