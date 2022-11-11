package com.example.springapp.service;

import com.example.springapp.entity.User;
import com.example.springapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

import javax.persistence.EntityNotFoundException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public User getLoggedUser() {
        // nie uzywa sie UserDetails
        // https://stackoverflow.com/questions/64514346/spring-boot-oauth2-resource-server-userdetailsservice
        // wiec lepiej chyba to z hasId
        // https://stackoverflow.com/questions/62662036/how-do-i-configure-preauthorize-to-recognize-the-id-of-my-logged-in-user

        JwtAuthenticationToken token = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        String email = String.valueOf(token.getTokenAttributes().get("email"));
        User user = userRepository.findByEmail(email).orElseThrow(() -> new EntityNotFoundException("Error while fetching user"));

        return user;
    }

    public void syncUser(User user) {
        if (user == null) {
            throw new EntityNotFoundException("Error while user sync");
        }

        User saveUser = user;
        Optional<User> optionalUser = userRepository.findByEmail(user.getEmail());

        if (optionalUser.isPresent()) {
            saveUser = optionalUser.get();
            saveUser.setFirstname(user.getFirstname());
            saveUser.setLastname(user.getLastname());
        }

        userRepository.save(saveUser);
    }

}
