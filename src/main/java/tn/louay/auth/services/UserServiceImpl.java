package tn.louay.auth.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tn.louay.auth.entities.Role;
import tn.louay.auth.entities.User;
import tn.louay.auth.entities.VerificationToken;
import tn.louay.auth.exceptions.ExpiredTokenException;
import tn.louay.auth.exceptions.InvalidTokenException;
import tn.louay.auth.repository.UserRepository;
import tn.louay.auth.repository.VerificationTokenRepository;

import java.util.Calendar;
import java.util.List;
import java.util.Random;

@Transactional
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRep;

    @Autowired
    VerificationTokenRepository verificationTokenRepo;

    @Autowired
    EmailService emailSender;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public Boolean hasAdmins() {
        return userRep.existsByRole(Role.ADMIN);
    }

    @Override
    public User findUserById(Integer id) {
        return userRep.findById(id).orElse(null);
    }

    @Override
    public List<User> findAllUsers() {
        return userRep.findAll();
    }

    @Override
    public User saveUser(User user) {

        boolean hasAdmins = userRep.existsByRole(Role.ADMIN);

        if (user.getRole() == Role.ADMIN && hasAdmins) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ADMIN"))) {
                throw new SecurityException("Only existing admins can create new admins");

            }
        }

        User existingUser = userRep.findByUsername(user.getUsername());
        if (existingUser == null) {
            existingUser = userRep.findByEmail(user.getEmail());
        }

        if (existingUser != null) {
            throw new IllegalArgumentException("User with the same username or email already exists");
        }

        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setEnabled(false);

        User newUser = userRep.save(user);

        String code = this.generateCode();
        VerificationToken token = new VerificationToken(code, newUser);
        verificationTokenRepo.save(token);

        System.out.println("UserServiceImpl.saveUser");

        sendEmailUser(newUser, token.getToken());

        return newUser;
    }

    @Override
    public User findUserByUsername(String username) {
        User existingUser = userRep.findByUsername(username);
        return existingUser;
    }

    @Override
    public User findUserByEmail(String email) {
        User existingUser = userRep.findByEmail(email);
        return existingUser;
    }

    @Override
    public User updateUser(Integer id, User user) {
        User existingUser = userRep.findById(id).orElse(null);
        if (existingUser == null) {
            return null;
        }

        existingUser.setUsername(user.getUsername());
        existingUser.setEmail(user.getEmail());
        existingUser.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        existingUser.setRole(user.getRole());

        return userRep.save(existingUser);
    }

    @Override
    public void deleteUser(Integer id) {
        userRep.deleteById(id);
    }

    @Override
    public User validateToken(String code) {

        VerificationToken token = verificationTokenRepo.findByToken(code);
        if (token == null) {
            throw new InvalidTokenException("Invalid Token");
        }

        User user = token.getUser();
        Calendar calendar = Calendar.getInstance();

        if ((token.getExpirationTime().getTime() - calendar.getTime().getTime()) <= 0) {
            verificationTokenRepo.delete(token);
            throw new ExpiredTokenException("expired Token");
        }

        user.setEnabled(true);
        userRep.save(user);

        return user;

    }

    public void sendEmailUser(User u, String code) {
        String emailBody = "Hello " + "<h1>" + u.getUsername() + "</h1>" +
                " Your verification code is: " + "<h1>" + code + "</h1>";
        emailSender.sendEmail(u.getEmail(), emailBody);
    }

    public String generateCode() {
        Random random = new Random();
        Integer code = 100000 + random.nextInt(900000);
        return code.toString();
    }

}