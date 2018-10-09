package com.xbd.xbdframework.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class XbdUsernamePasswordAuthenticationProcessingFilter extends UsernamePasswordAuthenticationFilter {
    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
    public static final String SPRING_SECURITY_FORM_CHECKCODE_KEY = "checkcode";
    public static final String SPRING_SECURITY_FORM_SIGNATURE_KEY = "signature";

    private SessionRegistry sessionRegistry;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter(SPRING_SECURITY_FORM_USERNAME_KEY);
        String password = request.getParameter(SPRING_SECURITY_FORM_PASSWORD_KEY);
        String caid = obtainCaid(request);
        String signature = "".equals(caid) ? null : caid;

        UsernamePasswordAuthenticationToken authRequest;

        if (signature != null) {
            authRequest = new SignatureAuthenticationToken(signature);

            sessionRegistry.registerNewSession(request.getSession().getId(), authRequest.getPrincipal());

            authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

            return getAuthenticationManager().authenticate(authRequest);
        } else {
            authRequest = new UsernamePasswordAuthenticationToken(username, password);

            sessionRegistry.registerNewSession(request.getSession().getId(), authRequest.getPrincipal());

            authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
            return authRequest;
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        /*
        HttpServletRequest rqt = (HttpServletRequest) req;
        HttpServletResponse rps = (HttpServletResponse) res;
        rqt.setCharacterEncoding("UTF-8");
        if (rqt.getRequestURI().indexOf("login") >= 0) {
            String caid = obtainCaid(rqt);

            if (StringUtils.isBlank(caid)) {
                String checkcode = rqt.getParameter(SPRING_SECURITY_FORM_CHECKCODE_KEY);

                String sessionCode = (String) rqt.getSession(true).getAttribute("RANDOM_CHECKCODE");

                if (!StringUtils.equals(checkcode, sessionCode)) {
                    rqt.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception("校验码不正确，登录失败！"));
                    rqt.getRequestDispatcher("/login?type=" + 2).forward(rqt, rps);
                } else {
                    super.doFilter(req, res, chain);
                }
            } else {
                super.doFilter(req, res, chain);
            }
        } else {
            super.doFilter(req, res, chain);
        }
        */

        super.doFilter(req, res, chain);
    }

    public String obtainCaid(HttpServletRequest request) {
        // 直接从request中获取，避免session一直记录是ca登陆导致账户登陆报错
        String caid = (String) request.getAttribute(SPRING_SECURITY_FORM_SIGNATURE_KEY);
        // request.getSession(true).removeAttribute(signatureHeader);
        return caid;
    }

    protected final void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }

    public SessionRegistry getSessionRegistry() {
        return sessionRegistry;
    }

    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }
}
