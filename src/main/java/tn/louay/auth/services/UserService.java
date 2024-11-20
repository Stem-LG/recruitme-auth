package tn.louay.auth.services;

import tn.louay.auth.entities.User;
import java.util.List;

public interface UserService {

    Boolean hasAdmins();

    User findUserById(Integer id);

    List<User> findAllUsers();

    User updateUser(Integer id, User user);

    void deleteUser(Integer id);

    User saveUser(User user);

    User findUserByUsername(String username);

    User findUserByEmail(String email);

    public User validateToken(String code);

    
}