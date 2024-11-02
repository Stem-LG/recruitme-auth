package tn.louay.auth.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import tn.louay.auth.dto.RegisterRequest;
import tn.louay.auth.dto.RegisterResponse;
import tn.louay.auth.entities.User;
import tn.louay.auth.services.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping("")
@CrossOrigin
public class AuthenticationController {

    @Autowired
    UserService userService;

    @PostMapping("/hasAdmins")
    public boolean hasAdmins() {
        return userService.hasAdmins();
    }

    @PostMapping("/register")
    public RegisterResponse register(@RequestBody RegisterRequest request) {

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(request.getPassword())
                .role(request.getRole())
                .build();

        User result = userService.saveUser(user);

        return RegisterResponse.builder()
                .username(result.getUsername())
                .email(result.getEmail())
                .role(result.getRole())
                .build();
    }

}
