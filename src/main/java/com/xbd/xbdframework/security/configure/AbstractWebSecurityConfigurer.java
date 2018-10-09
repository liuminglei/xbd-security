package com.xbd.xbdframework.security.configure;

import com.xbd.xbdframework.security.access.XbdAccessDecisionManager;
import com.xbd.xbdframework.security.access.intercept.XbdFilterInvocationSecurityMetadataSource;
import com.xbd.xbdframework.security.access.intercept.XbdFilterSecurityInterceptor;
import com.xbd.xbdframework.security.authentication.XbdUsernamePasswordAuthenticationProcessingFilter;
import com.xbd.xbdframework.security.authentication.dao.XbdDaoAuthenticationProvider;
import com.xbd.xbdframework.security.core.userdetails.XbdUserDetailsService;
import com.xbd.xbdframework.security.service.ResourcesLoaderService;
import com.xbd.xbdframework.security.service.UserLoaderService;
import com.xbd.xbdframework.security.web.authentication.XbdAuthenctiationFailureHandler;
import com.xbd.xbdframework.security.web.authentication.XbdAuthenctiationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.session.*;

public abstract class AbstractWebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    private final String loginProcessingUrl;
    private final String loginPage;
    private final String defaultSuccessUrl;
    private final String defaultFailureUrl;
    private final String defaultSsoLoginUrl;
    private final String sessionInvalidUrl;
    private final String sessionExpiredUrl;
    private final String[] unAuthenticateUrls;
    private final String[] webIgnoreUrls;
    private final int maximumSessions;
    private final boolean maxSessionsPreventsLogin;
    private final boolean logoutClearAuthentication;
    private final boolean logoutInvalidateHttpSession;

    public AbstractWebSecurityConfigurer() {
        this.loginProcessingUrl = "/authenticate";
        this.loginPage = "/login";
        this.defaultSuccessUrl = "/index";
        this.defaultFailureUrl = loginPage + "?type=" + LoginType.FAILURE.getType();
        this.defaultSsoLoginUrl = "/sso/login";
        this.sessionInvalidUrl = loginPage + "?type=" + LoginType.SESSIONINVALID.getType();
        this.sessionExpiredUrl = loginPage + "?type=" + LoginType.SESSIONEXPIRED.getType();
        this.unAuthenticateUrls = new String[] { loginPage };
        this.webIgnoreUrls = new String[] { "/config/**", "/css/**", "/fonts/**", "/img/**", "/js/**" };
        this.maximumSessions = 1;
        this.maxSessionsPreventsLogin = true;
        this.logoutClearAuthentication = true;
        this.logoutInvalidateHttpSession = true;
    }

    protected abstract UserLoaderService userLoaderService();

    public abstract ResourcesLoaderService resourcesLoaderService();

    public XbdUserDetailsService xbdUserDetailsService() {
        XbdUserDetailsService xbdUserDetailsService = new XbdUserDetailsService();

        xbdUserDetailsService.setUserLoaderService(userLoaderService());

        return xbdUserDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public XbdFilterInvocationSecurityMetadataSource xbdFilterInvocationSecurityMetadataSource() {
        XbdFilterInvocationSecurityMetadataSource xbdFilterInvocationSecurityMetadataSource = new XbdFilterInvocationSecurityMetadataSource();
        xbdFilterInvocationSecurityMetadataSource.setResourcesLoaderService(resourcesLoaderService());
        return xbdFilterInvocationSecurityMetadataSource;
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers(webIgnoreUrls);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginProcessingUrl(loginProcessingUrl)
                .loginPage(loginPage).permitAll()
                .and().authorizeRequests()
                .anyRequest().authenticated()
                .antMatchers(defaultSsoLoginUrl).permitAll()
                .antMatchers(unAuthenticateUrls).permitAll()
                .and().sessionManagement().invalidSessionStrategy(invalidSessionStrategy())
                .maximumSessions(maximumSessions).maxSessionsPreventsLogin(maxSessionsPreventsLogin)
                .and()
//                .and().rememberMe().tokenValiditySeconds(1209600)
                .and().logout().clearAuthentication(logoutClearAuthentication).invalidateHttpSession(logoutInvalidateHttpSession)
                .and().csrf().disable();

        http.headers().frameOptions().disable();

        http.addFilterAt(xbdUsernamePasswordAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterAt(concurrentSessionFilter(), ConcurrentSessionFilter.class);
        http.addFilterAt(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(xbdDaoAuthenticationProvider());
    }

    @Override
    public AuthenticationManager authenticationManager() {
        return (authentication -> xbdDaoAuthenticationProvider().authenticate(authentication));
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    protected InvalidSessionStrategy invalidSessionStrategy() {
        return new SimpleRedirectInvalidSessionStrategy(sessionInvalidUrl);
    }

    protected SessionInformationExpiredStrategy sessionInformationExpiredStrategy() {
        return new SimpleRedirectSessionInformationExpiredStrategy(sessionExpiredUrl);
    }

    protected ConcurrentSessionFilter concurrentSessionFilter() {
        return new ConcurrentSessionFilter(sessionRegistry(), sessionInformationExpiredStrategy());
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public XbdAccessDecisionManager xbdAccessDecisionManager() {
        return new XbdAccessDecisionManager();
    }

    @Bean
    public XbdFilterSecurityInterceptor customFilterSecurityInterceptor() {
        XbdFilterSecurityInterceptor customFilterSecurityInterceptor = new XbdFilterSecurityInterceptor();
        customFilterSecurityInterceptor.setSecurityMetadataSource(xbdFilterInvocationSecurityMetadataSource());
        customFilterSecurityInterceptor.setAuthenticationManager(authenticationManager());
        customFilterSecurityInterceptor.setAccessDecisionManager(xbdAccessDecisionManager());

        return customFilterSecurityInterceptor;
    }

    @Bean
    public XbdDaoAuthenticationProvider xbdDaoAuthenticationProvider() {
        XbdDaoAuthenticationProvider xbdDaoAuthenticationProvider = new XbdDaoAuthenticationProvider();
        xbdDaoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        xbdDaoAuthenticationProvider.setUserDetailsService(xbdUserDetailsService());
        return xbdDaoAuthenticationProvider;
    }

    @Bean
    public XbdUsernamePasswordAuthenticationProcessingFilter xbdUsernamePasswordAuthenticationProcessingFilter() {
        XbdUsernamePasswordAuthenticationProcessingFilter customUsernamePasswordAuthenticationProcessingFilter = new XbdUsernamePasswordAuthenticationProcessingFilter();

        customUsernamePasswordAuthenticationProcessingFilter.setFilterProcessesUrl(loginProcessingUrl);
        customUsernamePasswordAuthenticationProcessingFilter.setAuthenticationManager(authenticationManager());
        customUsernamePasswordAuthenticationProcessingFilter.setAuthenticationSuccessHandler(xbdAuthenctiationSuccessHandler());
        customUsernamePasswordAuthenticationProcessingFilter.setAuthenticationFailureHandler(xbdAuthenctiationFailureHandler());
        customUsernamePasswordAuthenticationProcessingFilter.setSessionAuthenticationStrategy(concurrentSessionControlAuthenticationStrategy());
        customUsernamePasswordAuthenticationProcessingFilter.setSessionRegistry(sessionRegistry());

        return customUsernamePasswordAuthenticationProcessingFilter;
    }

    protected ConcurrentSessionControlAuthenticationStrategy concurrentSessionControlAuthenticationStrategy() {
        ConcurrentSessionControlAuthenticationStrategy concurrentSessionControlAuthenticationStrategy = new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry());
        return concurrentSessionControlAuthenticationStrategy;
    }

    protected XbdAuthenctiationSuccessHandler xbdAuthenctiationSuccessHandler() {
        XbdAuthenctiationSuccessHandler xbdAuthenctiationSuccessHandler = new XbdAuthenctiationSuccessHandler();

        xbdAuthenctiationSuccessHandler.setDefaultTargetUrl(defaultSuccessUrl);

        return xbdAuthenctiationSuccessHandler;
    }

    protected XbdAuthenctiationFailureHandler xbdAuthenctiationFailureHandler() {
        XbdAuthenctiationFailureHandler xbdAuthenctiationFailureHandler = new XbdAuthenctiationFailureHandler();

        xbdAuthenctiationFailureHandler.setDefaultFailureUrl(defaultFailureUrl);

        return xbdAuthenctiationFailureHandler;
    }

}
