package com.xaaef.molly.security.demo1.config;

import com.xaaef.molly.security.demo1.email.EmailCodeSecurityConfig;
import com.xaaef.molly.security.demo1.sms.SmsCodeSecurityConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.xaaef.molly.security.demo1.email.EmailCodeAuthenticationFilter.EMAIL_ANT_PATH_REQUEST_MATCHER;
import static com.xaaef.molly.security.demo1.sms.SmsCodeAuthenticationFilter.SMS_ANT_PATH_REQUEST_MATCHER;


@Slf4j
@Configuration
@EnableWebSecurity
public class DefaultSecurityConfig {

    public static final String LOGIN_URL = "/login";

    // 不需要认证的路径
    public static final String[] WHITE_LIST = {
            "/actuator/**", "/v2/api-docs", "/v3/api-docs/**", "/doc.html",
            "/configuration/ui", "/swagger-resources", "/configuration/security", "/webjars/**",
            "/swagger-resources/configuration/ui", "/swagger-ui.html",
            "/css/**", "/js/**", "/img/**", "/font/**", "/error", "/error/**"
    };


    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          SmsCodeSecurityConfig smsCodeSecurityConfig,
                                                          EmailCodeSecurityConfig emailCodeSecurityConfig) throws Exception {
        http
                .authorizeRequests(a -> a
                        // 跨域的调用
                        .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        //  获取白名单（不进行权限验证）
                        .antMatchers(WHITE_LIST).permitAll()
                        .requestMatchers(SMS_ANT_PATH_REQUEST_MATCHER, EMAIL_ANT_PATH_REQUEST_MATCHER).permitAll()
                        //  其他的请求全部要认证
                        .anyRequest()
                        .authenticated()
                )
                .formLogin(a -> a.loginPage(LOGIN_URL)
                        .defaultSuccessUrl("/user/info")
                        .permitAll()
                )
                .logout(a -> a.logoutSuccessUrl("/logout/success")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                )
                .apply(smsCodeSecurityConfig)
                .and()
                .apply(emailCodeSecurityConfig);
        return http.build();
    }


    @Bean
    public UserDetailsService userDetailsService() {
        var user1 = User.withUsername("admin")
                .password("{noop}admin")
                .roles("USER")
                .build();

        var user2 = User.withUsername("15071525211")
                .password("123456")
                .roles("USER", "TEST")
                .build();

        var user3 = User.withUsername("test123@gmail.com")
                .password("123456")
                .roles("USER", "DEV")
                .build();

        return new InMemoryUserDetailsManager(user1, user2, user3);
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


}
