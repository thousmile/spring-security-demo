package com.xaaef.molly.security.demo1.email;

import cn.hutool.core.util.StrUtil;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

/**
 * 邮箱验证码，请求拦截器
 */

public class EmailCodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    // 设置拦截 /email/login 登录接口
    public static final AntPathRequestMatcher EMAIL_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/email/login", "POST");

    private final static String EMAIL_REG_EXP = "^(\\w|\\.|-|\\+)+@(\\w|-)+(\\.(\\w|-)+)+$";

    private final static String CODE_REG_EXP = "\\d{6}";

    /**
     * TODO 邮箱账号
     */
    private String emailParameter = "email";

    /**
     * TODO 邮箱验证码
     */
    private String codeParameter = "code";

    private boolean postOnly = true;


    public EmailCodeAuthenticationFilter() {
        super(EMAIL_ANT_PATH_REQUEST_MATCHER);
    }


    public EmailCodeAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(EMAIL_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            var email = this.obtainMobile(request);
            if (StrUtil.isBlank(email)) {
                throw new AuthenticationServiceException("邮箱账号必须填写！");
            }
            if (!Pattern.matches(EMAIL_REG_EXP, email)) {
                throw new AuthenticationServiceException(StrUtil.format("邮箱账号 {} 格式错误！", email));
            }
            var code = this.obtainCode(request);
            if (StrUtil.isBlank(code)) {
                throw new AuthenticationServiceException("验证码必须填写！");
            }
            if (!Pattern.matches(CODE_REG_EXP, code)) {
                throw new AuthenticationServiceException("验证码必须是6位数字！");
            }
            var authRequest = EmailCodeAuthenticationToken.unauthenticated(email, code);
            setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }


    protected void setDetails(HttpServletRequest request, EmailCodeAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }


    @Nullable
    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(this.emailParameter);
    }

    @Nullable
    protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(this.codeParameter);
    }

    public void setEmailParameter(String emailParameter) {
        this.emailParameter = emailParameter;
    }

    public void setCodeParameter(String codeParameter) {
        this.codeParameter = codeParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

}
