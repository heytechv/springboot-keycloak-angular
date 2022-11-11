package com.example.springapp.controller;

import com.example.springapp.entity.User;
import com.example.springapp.service.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequiredArgsConstructor
public class WebController {

    private static final Logger logger = LoggerFactory.getLogger(WebController.class);

    private final UserService userService;

    @GetMapping(path = "/userInfo1")
    public String getUserInfo1() {
        User user = userService.getLoggedUser();

        return "UserInfo1: " + user.getFirstname() + " " + user.getLastname() + ", " + user.getEmail();
    }

    @GetMapping("/userInfo2")
    public String getUserInfo2(JwtAuthenticationToken auth) {
        String firstname = auth.getTokenAttributes().get("given_name").toString();
        String lastname = auth.getTokenAttributes().get("family_name").toString();
        String email = auth.getTokenAttributes().get("email").toString();
        String authorities = auth.getAuthorities().toString();

        return "UserInfo2: " + firstname + " " + lastname + ", " + email + ", " + authorities ;
    }

}
