package com.example.springapp.security;

import com.example.springapp.entity.User;
import com.example.springapp.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class JwtUserSyncFilter extends OncePerRequestFilter {

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try {
            JwtAuthenticationToken token = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

            String firstname = String.valueOf(token.getTokenAttributes().get("given_name"));
            String lastname = String.valueOf(token.getTokenAttributes().get("family_name"));
            String email = String.valueOf(token.getTokenAttributes().get("email"));
            User.Gender gender = token.getTokenAttributes().get("gender") == null ? null :
                    User.Gender.valueOf(String.valueOf(token.getTokenAttributes().get("gender")).toUpperCase());

            User user = User.builder()
                    .firstname(firstname)
                    .lastname(lastname)
                    .email(email)
                    .gender(gender)
                    .build();

            userService.syncUser(user);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to auth user");
        }

        filterChain.doFilter(request, response);
    }

}
