package me.crespel.karaplan.service.impl;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.repository.PlaylistRepo;
import me.crespel.karaplan.repository.UserRepo;
import me.crespel.karaplan.service.PlaylistService;

@Service
public class PlaylistServiceImpl implements PlaylistService {

	@Autowired
	protected UserRepo userRepo;

	@Autowired
	protected PlaylistRepo playlistRepo;

	@Override
	public Set<Playlist> findAll() {
		return Sets.newLinkedHashSet(playlistRepo.findAll());
	}

	@Override
	public Set<Playlist> findAll(Pageable pageable) {
		return Sets.newLinkedHashSet(playlistRepo.findAll(pageable));
	}

	@Override
	public Set<Playlist> findAllAuthorized(Pageable pageable, User user) {
		return Sets.newLinkedHashSet(playlistRepo.findAllByRestrictedOrAuthorizedUsersId(false, user.getId()));
	}

	@Override
	public Optional<Playlist> findById(Long id) {
		return findById(id, false);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Playlist> findById(Long id, boolean includeSongs) {
		Optional<Playlist> playlist = playlistRepo.findById(id);
		if (playlist.isPresent() && includeSongs) {
			playlist.get().getSongs().size(); // Force eager load
		}
		return playlist;
	}

	@Override
	@Transactional
	public Playlist create(String name, User user, boolean restricted) {
		Playlist playlist = new Playlist().setName(name).setRestricted(restricted);
		if (restricted) {
			playlist.setAccessKey(UUID.randomUUID().toString());
			playlist.getAuthorizedUsers().add(user);
		}
		return playlistRepo.save(playlist);
	}

	@Override
	@Transactional
	public Playlist save(Playlist playlist) {
		playlist.updateStats();
		return playlistRepo.save(playlist);
	}

	@Override
	@Transactional
	public Playlist addSong(Playlist playlist, Song song) {
		playlist.getSongs().add(song);
		song.getPlaylists().add(playlist);
		song.updateStats();
		return save(playlist);
	}

	@Override
	@Transactional
	public Playlist removeSong(Playlist playlist, Song song) {
		playlist.getSongs().remove(song);
		song.getPlaylists().remove(playlist);
		song.updateStats();
		return save(playlist);
	}

	@Override
	@Transactional
	public Playlist addUser(Playlist playlist, User user, String accessKey) {
		if (playlist.getRestricted() && playlist.getAccessKey() != null) {
			if (playlist.getAccessKey().equals(accessKey)) {
				if (!playlist.getAuthorizedUsers().contains(user)) {
					playlist.getAuthorizedUsers().add(user);
					return playlistRepo.save(playlist);
				}
			} else {
				throw new BusinessException("Invalid playlist access key");
			}
		}
		return playlist;
	}

	@Override
	@Transactional
	public void delete(Playlist playlist) {
		playlistRepo.delete(playlist);
	}

}
