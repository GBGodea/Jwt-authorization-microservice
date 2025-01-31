package com.godea.authorization.services;

import com.fasterxml.jackson.annotation.JacksonAnnotationsInside;
import com.godea.authorization.models.User;
import com.godea.authorization.models.dto.JwtRequest;
import com.godea.authorization.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;
import java.util.Optional;

@Service
public class AuthService {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public String auth(JwtRequest request) {
        Optional<User> userOpt = userRepository.findUserByEmail(request.getEmail());

        if(userOpt.isEmpty()) {
            throw new NoSuchElementException("User not found");
        }

        if(!passwordEncoder.matches(request.getPassword(), userOpt.get().getPassword())) {
            throw new RuntimeException("Invalid Password");
        }

        return jwtService.generate(userOpt.get());
    }
}
