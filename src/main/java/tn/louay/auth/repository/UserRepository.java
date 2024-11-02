package tn.louay.auth.repository;

import tn.louay.auth.entities.User;
import tn.louay.auth.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
  User findByUsername(String username);

  User findByEmail(String email);

  boolean existsByRole(Role role);
}