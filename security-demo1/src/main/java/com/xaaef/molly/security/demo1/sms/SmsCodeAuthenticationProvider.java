package com.xaaef.molly.security.demo1.sms;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

import java.util.stream.Stream;

/**
 * 短信登录校验器
 */

@Slf4j
public class SmsCodeAuthenticationProvider implements AuthenticationProvider {

    protected final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private final UserDetailsService userDetailsService;

    public SmsCodeAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(SmsCodeAuthenticationToken.class, authentication, () ->
                this.messages.getMessage("SmsCodeAuthenticationProvider.onlySupports", "Only SmsCodeAuthenticationToken is supported")
        );
        var auth = (SmsCodeAuthenticationToken) authentication;
        var mobile = (String) auth.getPrincipal();
        var code = (String) auth.getCredentials();
        var collect = Stream.of("read", "write").map(SimpleGrantedAuthority::new).toList();

        var loginUser = userDetailsService.loadUserByUsername(mobile);
        if (!StringUtils.equals(loginUser.getPassword(), code)) {
            throw new AuthenticationServiceException("sms code err : " + code);
        }

        var authenticated = SmsCodeAuthenticationToken.authenticated(loginUser, mobile, collect);
        authenticated.setDetails(auth.getDetails());
        log.info("mobile: {}  code: {}  isAuthenticated: {}", mobile, code, authenticated.isAuthenticated());
        return authenticated;
    }


    @Override
    public boolean supports(Class<?> authentication) {
        //第二步拦截封装了WxLoginAuthenticationToken，此处校验，如果是该类型，则在该处理器做登录校验
        return (SmsCodeAuthenticationToken.class.isAssignableFrom(authentication));
    }


}
