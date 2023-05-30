package com.xaaef.molly.security.demo1.email;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.stereotype.Component;


@Slf4j
@Component
@AllArgsConstructor
public class EmailCodeSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final UserDetailsService userDetailsService;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        var filter = new EmailCodeAuthenticationFilter();
        var sharedObject = http.getSharedObject(AuthenticationManager.class);
        filter.setAuthenticationManager(sharedObject);

        var handler = new EmailCodeAuthenticationHandler();
        filter.setAuthenticationFailureHandler(handler);
        filter.setAuthenticationSuccessHandler(handler);
        filter.setSecurityContextRepository(
                new DelegatingSecurityContextRepository(
                        new RequestAttributeSecurityContextRepository(),
                        new HttpSessionSecurityContextRepository())
        );

        var provider = new EmailCodeAuthenticationProvider(userDetailsService);
        http.authenticationProvider(provider)
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }


}
