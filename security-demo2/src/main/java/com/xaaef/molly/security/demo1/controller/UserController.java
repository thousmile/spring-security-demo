package com.xaaef.molly.security.demo1.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import com.xaaef.molly.security.demo1.util.JwtSecurityUtils;

@Slf4j
@RequestMapping
@RestController
public class UserController {


    /**
     * TODO 获取用户信息
     */
    @RequestMapping("/user/info")
    @ResponseBody
    public Object userInfo() {
        return JwtSecurityUtils.getLoginUser();
    }


}
