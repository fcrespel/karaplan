package me.crespel.karaplan.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import me.crespel.karaplan.domain.User;

public interface UserRepo extends PagingAndSortingRepository<User, Long> {

}
