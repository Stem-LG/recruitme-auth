package tn.louay.auth.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tn.louay.auth.entities.Role;
import tn.louay.auth.entities.User;
import tn.louay.auth.repository.UserRepository;
import java.util.List;

@Transactional
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRep;

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
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }

        boolean hasAdmins = userRep.existsByRole(Role.ADMIN);

        // Check if this user wants to be an admin
        if (user.getRole() == Role.ADMIN) {
            if (hasAdmins) {
                // If admins exist, check if requester is an admin
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                System.out.println(auth.getAuthorities());
                // print user name
                System.out.println(auth.getName());
                if (auth == null || !auth.getAuthorities().stream()
                        .anyMatch(a -> a.getAuthority().equals("ADMIN"))) {
                    throw new SecurityException("Only existing admins can create new admins");
                }
            }
            // If no admins exist, allow this first admin request
        }

        User existingUser = userRep.findByUsername(user.getUsername());
        if (existingUser == null) {
            existingUser = userRep.findByEmail(user.getEmail());
        }

        if (existingUser != null) {
            throw new IllegalArgumentException("User with the same username or email already exists");
        }

        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        return userRep.save(user);
    }

    @Override
    public User findUserByUsername(String username) {

        User existingUser = userRep.findByUsername(username);
        if (existingUser == null) {
            existingUser = userRep.findByEmail(username);
        }

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

}