package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.repository.PagingAndSortingRepository;

import me.crespel.karaplan.domain.User;

public interface UserRepo extends PagingAndSortingRepository<User, Long> {

	Optional<User> findByUsername(String username);

}
