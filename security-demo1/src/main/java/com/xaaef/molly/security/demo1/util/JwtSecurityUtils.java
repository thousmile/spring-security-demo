package com.xaaef.molly.security.demo1.util;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * <p>
 * 安全服务工具类
 * </p>
 *
 * @author Wang Chen Chen
 * @version 1.0
 * @date 2021/7/5 10:50
 */

public class JwtSecurityUtils {

    /**
     * 获取Authentication
     */
    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }


    /**
     * 经过认证！
     */
    public static boolean isAuthenticated() {
        var auth = getAuthentication();
        return auth != null && !(auth instanceof AnonymousAuthenticationToken) && auth.isAuthenticated();
    }


    /**
     * 获取用户
     **/
    public static Object getLoginUser() {
        if (isAuthenticated()) {
            return getAuthentication().getPrincipal();
        } else {
            throw new AuthenticationCredentialsNotFoundException("用户暂无登录！");
        }
    }

}
