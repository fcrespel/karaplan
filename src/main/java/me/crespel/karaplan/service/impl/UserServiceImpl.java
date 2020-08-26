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
import me.crespel.karaplan.service.PlaylistService;
import me.crespel.karaplan.service.SongCommentService;
import me.crespel.karaplan.service.SongService;
import me.crespel.karaplan.service.UserService;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	protected UserRepo userRepo;
	
	@Autowired
	protected SongService songService;

	@Autowired
	protected PlaylistService playlistService;
	
	@Autowired
	protected SongCommentService songCommentService;
	
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
	public void deleteAccount(boolean deleteComments, User user) {
		songService.deleteUserVotes(user);
		playlistService.findAll(user).forEach(playlist -> playlistService.removeUser(playlist, user));
		if(deleteComments) {
			songCommentService.findAll(user).forEach(comment -> songService.removeComment(comment.getSong(), user, comment.getId()));
		}
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
