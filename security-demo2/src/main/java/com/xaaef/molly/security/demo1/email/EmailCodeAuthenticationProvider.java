package com.xaaef.molly.security.demo1.email;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 邮箱登录校验器
 */

@Slf4j
public class EmailCodeAuthenticationProvider implements AuthenticationProvider {

    protected final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private final UserDetailsService userDetailsService;

    public EmailCodeAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(EmailCodeAuthenticationToken.class, authentication, () ->
                this.messages.getMessage("EmailCodeAuthenticationProvider.onlySupports", "Only EmailCodeAuthenticationToken is supported")
        );
        var auth = (EmailCodeAuthenticationToken) authentication;
        var email = (String) auth.getPrincipal();
        var code = (String) auth.getCredentials();
        var collect = Stream.of("read", "write").map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        var loginUser = userDetailsService.loadUserByUsername(email);
        if (!StringUtils.equals(loginUser.getPassword(), code)) {
            throw new AuthenticationServiceException("email code err : " + code);
        }
        var authenticated = EmailCodeAuthenticationToken.authenticated(loginUser, email, collect);
        authenticated.setDetails(auth.getDetails());
        log.info("email: {}  code: {}  isAuthenticated: {}", email, code, authenticated.isAuthenticated());
        return authenticated;
    }


    @Override
    public boolean supports(Class<?> authentication) {
        //第二步拦截封装了WxLoginAuthenticationToken，此处校验，如果是该类型，则在该处理器做登录校验
        return (EmailCodeAuthenticationToken.class.isAssignableFrom(authentication));
    }


}
