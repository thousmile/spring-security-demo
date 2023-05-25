package com.xaaef.molly.security.demo1.sms;

import cn.hutool.core.util.StrUtil;
import jakarta.annotation.Nullable;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.regex.Pattern;

/**
 * 短信验证码，请求拦截器
 */

public class SmsCodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    // 设置拦截/sms/login短信登录接口
    public static final AntPathRequestMatcher SMS_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/sms/login", "POST");

    private final static String MOBILE_REG_EXP = "1[3-9]\\d{9}";

    private final static String CODE_REG_EXP = "\\d{6}";

    /**
     * TODO 手机号码
     */
    private String mobileParameter = "mobile";

    /**
     * TODO 短信验证码
     */
    private String codeParameter = "code";

    private boolean postOnly = true;


    public SmsCodeAuthenticationFilter() {
        super(SMS_ANT_PATH_REQUEST_MATCHER);
    }


    public SmsCodeAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(SMS_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            var mobile = this.obtainMobile(request);
            if (StrUtil.isBlank(mobile)) {
                throw new AuthenticationServiceException("手机号码必须填写！");
            }
            if (!Pattern.matches(MOBILE_REG_EXP, mobile)) {
                throw new AuthenticationServiceException(StrUtil.format("手机号码 {} 格式错误！", mobile));
            }
            var code = this.obtainCode(request);
            if (StrUtil.isBlank(code)) {
                throw new AuthenticationServiceException("验证码必须填写！");
            }
            if (!Pattern.matches(CODE_REG_EXP, code)) {
                throw new AuthenticationServiceException("验证码必须是6位数字！");
            }
            var authRequest = SmsCodeAuthenticationToken.unauthenticated(mobile, code);
            setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }


    protected void setDetails(HttpServletRequest request, SmsCodeAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }


    @Nullable
    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(this.mobileParameter);
    }

    @Nullable
    protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(this.codeParameter);
    }

    public void setMobileParameter(String mobileParameter) {
        this.mobileParameter = mobileParameter;
    }

    public void setCodeParameter(String codeParameter) {
        this.codeParameter = codeParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

}
