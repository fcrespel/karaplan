package me.crespel.karaplan.service.impl;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.repository.UserRepo;
import me.crespel.karaplan.service.UserService;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	protected UserRepo userRepo;

	@Override
	public Set<User> findAll() {
		return Sets.newLinkedHashSet(userRepo.findAll());
	}

	@Override
	public Set<User> findAll(Pageable pageable) {
		return Sets.newLinkedHashSet(userRepo.findAll(pageable));
	}

	@Override
	public Optional<User> findById(Long id) {
		return userRepo.findById(id);
	}

	@Override
	public Optional<User> findByProviderAndUsername(String provider, String username) {
		return userRepo.findByProviderAndUsername(provider, username);
	}

	@Override
	@Transactional
	public User save(User user) {
		return userRepo.save(user);
	}

	@Override
	public void deleteAccount(User user) {
		user.setUsername("deletedUser");
		user.setDisplayName("Deleted User");
		user.setFirstName(null);
		user.setLastName(null);
		user.setFullName(null);
		user.setEmail(null);
		user.setLocale(null);
		user.setProvider("");
		userRepo.save(user);
	}

}
