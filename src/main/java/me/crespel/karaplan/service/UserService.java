package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.User;

public interface UserService {

	Set<User> findAll();

	Set<User> findAll(Pageable pageable);

	Optional<User> findById(Long id);

	Optional<User> findByUsername(String username);

	User save(User user);

}
