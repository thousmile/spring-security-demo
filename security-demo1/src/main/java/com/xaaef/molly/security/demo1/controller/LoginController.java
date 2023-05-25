package com.xaaef.molly.security.demo1.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import javax.imageio.ImageIO;
import java.io.IOException;
import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;

import static com.xaaef.molly.security.demo1.config.DefaultSecurityConfig.LOGIN_URL;


@Slf4j
@Controller
@AllArgsConstructor
public class LoginController {

    /**
     * TODO 首页
     */
    @GetMapping(value = {"", "index", "home"})
    public ModelAndView index() {
        return new ModelAndView("index");
    }


    /**
     * TODO 登录页面
     */
    @GetMapping(LOGIN_URL)
    public ModelAndView login() {
        return new ModelAndView("login");
    }


    /**
     * TODO 退出登录成功页面
     */
    @GetMapping("/logout/success")
    public ModelAndView logoutSuccess() {
        return new ModelAndView("index");
    }



}
