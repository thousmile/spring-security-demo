package com.xaaef.molly.security.demo1.email;

import com.xaaef.molly.security.demo1.util.JsonUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;

/**
 * <p>
 * </p>
 *
 * @author WangChenChen
 * @version 1.1
 * @date 2023/5/24 11:15
 */

@Slf4j
public class EmailCodeAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    private AuthenticationSuccessHandler defaultSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();

    /**
     * 登录成功
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {
        log.info("Email 登录成功，保存登录信息到 session 中.....");
        this.defaultSuccessHandler.onAuthenticationSuccess(request, response, authResult);
    }

    /**
     * 登录失败
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        var anonymous = new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        this.defaultSuccessHandler.onAuthenticationSuccess(request, response, anonymous);
    }

    public void setDefaultSuccessHandler(AuthenticationSuccessHandler defaultSuccessHandler) {
        this.defaultSuccessHandler = defaultSuccessHandler;
    }

}
