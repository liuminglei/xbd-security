package com.xbd.xbdframework.security.authentication.dao;

import com.xbd.xbdframework.security.authentication.SignatureAuthenticationToken;
import com.xbd.xbdframework.security.authentication.UsernameAuthenticationToken;
import com.xbd.xbdframework.security.core.userdetails.SignatureUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

public class XbdDaoAuthenticationProvider extends DaoAuthenticationProvider {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private SignatureUserDetailsService signatureUserDetailsService;

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        if (!(authentication instanceof SignatureAuthenticationToken) && !(authentication instanceof UsernameAuthenticationToken)) {
            if (authentication.getCredentials() == null) {
                logger.debug("认证失败: 密码为空！");
                throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "用户名或密码错误！"));
            }

            String presentedPassword = authentication.getCredentials().toString();

            logger.info("认证携带密码为{}，数据库存储密码为{}", new Object[]{presentedPassword, userDetails.getPassword()});

            if (!this.getPasswordEncoder().matches(presentedPassword, userDetails.getPassword())) {
                logger.debug("认证失败: 密码不正确！");
                throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "用户名或密码错误！"));
            }
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if ((authentication instanceof SignatureAuthenticationToken)) {
            SignatureAuthenticationToken customUsernameAuthenticationToken = (SignatureAuthenticationToken) authentication;

            UserDetails loadedUser = this.signatureUserDetailsService.loadUserBySignature(customUsernameAuthenticationToken.getSignature());
            Authentication resut = createSuccessAuthentication(loadedUser, authentication, loadedUser);
            SecurityContextHolder.getContext().setAuthentication(resut);

            return resut;
        } else if (authentication instanceof UsernameAuthenticationToken) {
            UsernameAuthenticationToken usernameAuthenticationToken = (UsernameAuthenticationToken) authentication;

            UserDetails loadedUser = getUserDetailsService().loadUserByUsername((String) usernameAuthenticationToken.getPrincipal());
            Authentication resut = createSuccessAuthentication(loadedUser, authentication, loadedUser);
            SecurityContextHolder.getContext().setAuthentication(resut);

            return resut;
        } else {
            SecurityContextHolder.getContext().setAuthentication(authentication);

            return authentication.isAuthenticated() ? authentication : super.authenticate(authentication);
        }
    }

    public SignatureUserDetailsService getSignatureUserDetailsService() {
        return signatureUserDetailsService;
    }

    public void setSignatureUserDetailsService(SignatureUserDetailsService signatureUserDetailsService) {
        this.signatureUserDetailsService = signatureUserDetailsService;
    }

}
