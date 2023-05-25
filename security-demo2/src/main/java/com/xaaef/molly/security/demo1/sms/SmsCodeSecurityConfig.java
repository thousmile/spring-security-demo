package com.xaaef.molly.security.demo1.sms;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;


@Slf4j
@Component
@AllArgsConstructor
public class SmsCodeSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final UserDetailsService userDetailsService;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        var filter = new SmsCodeAuthenticationFilter();
        var sharedObject = http.getSharedObject(AuthenticationManager.class);
        filter.setAuthenticationManager(sharedObject);

        var handler = new SmsCodeAuthenticationHandler();
        filter.setAuthenticationFailureHandler(handler);
        filter.setAuthenticationSuccessHandler(handler);

        var provider = new SmsCodeAuthenticationProvider(userDetailsService);
        http.authenticationProvider(provider)
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }


}
