package tn.louay.auth.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;

import tn.louay.auth.dto.RegisterRequest;
import tn.louay.auth.dto.RegisterResponse;
import tn.louay.auth.entities.User;
import tn.louay.auth.exceptions.ErrorDetails;
import tn.louay.auth.exceptions.ExpiredTokenException;
import tn.louay.auth.exceptions.InvalidTokenException;
import tn.louay.auth.services.UserService;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
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

    @GetMapping("/verify/{token}")
    public User verifyEmail(@PathVariable("token") String token) {
        return userService.validateToken(token);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ErrorDetails> handleInvalidTokenException(InvalidTokenException exception,
            WebRequest webRequest) {
        ErrorDetails errorDetails = new ErrorDetails(
                LocalDateTime.now(),
                exception.getMessage(),
                webRequest.getDescription(false),
                "INVALID_TOKEN");
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(ExpiredTokenException.class)
    public ResponseEntity<ErrorDetails> handleExpiredTokenException(ExpiredTokenException exception,
            WebRequest webRequest) {
        ErrorDetails errorDetails = new ErrorDetails(
                LocalDateTime.now(),
                exception.getMessage(),
                webRequest.getDescription(false),
                "EXPIRED_TOKEN");
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

}
