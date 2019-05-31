package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.User;

public interface UserRepo extends JpaRepository<User, Long> {

	Optional<User> findByProviderAndUsername(String provider, String username);

}
