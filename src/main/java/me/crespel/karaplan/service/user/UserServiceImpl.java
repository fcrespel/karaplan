package me.crespel.karaplan.service.user;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.repository.UserRepo;
import me.crespel.karaplan.service.PlaylistService;
import me.crespel.karaplan.service.SongService;
import me.crespel.karaplan.service.UserService;

@Service
public class UserServiceImpl implements UserService {

	private final UserRepo userRepo;
	private final SongService songService;
	private final PlaylistService playlistService;

	public UserServiceImpl(UserRepo userRepo, SongService songService, PlaylistService playlistService) {
		this.userRepo = userRepo;
		this.songService = songService;
		this.playlistService = playlistService;
	}

	@Override
	@Transactional(readOnly = true)
	public Set<User> findAll() {
		return Sets.newLinkedHashSet(userRepo.findAll());
	}

	@Override
	@Transactional(readOnly = true)
	public Set<User> findAll(Pageable pageable) {
		return Sets.newLinkedHashSet(userRepo.findAll(pageable));
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<User> findById(Long id) {
		return userRepo.findById(id);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<User> findByProviderAndUsername(String provider, String username) {
		return userRepo.findByProviderAndUsername(provider, username);
	}

	@Override
	@Transactional
	public User save(User user) {
		return userRepo.save(user);
	}

	@Override
	@Transactional
	public void delete(User user, boolean deleteComments) {
		songService.removeUserVotes(user);
		playlistService.findAll(user).forEach(playlist -> playlistService.removeUser(playlist, user));
		if (deleteComments) {
			songService.removeUserComments(user);
			userRepo.delete(user);
		} else {
			user.setUsername("deleted");
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

}
