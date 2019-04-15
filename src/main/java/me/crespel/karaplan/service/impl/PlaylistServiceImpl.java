package me.crespel.karaplan.service.impl;

import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.PlaylistSong;
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
	public Set<Playlist> findAll(Pageable pageable, User user) {
		return playlistRepo.findAll(pageable).stream()
				.map(playlist -> {
					if (!isMember(user, playlist)) {
						playlist.setAccessKey(null);
					}
					return playlist;
				})
				.collect(Collectors.toCollection(LinkedHashSet::new));
	}

	@Override
	public Set<Playlist> findAllAuthorized(Pageable pageable, User user) {
		return Sets.newLinkedHashSet(playlistRepo.findAllByRestrictedOrMembersId(false, user.getId(), pageable));
	}

	@Override
	public Optional<Playlist> findById(Long id) {
		return findById(id, false);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Playlist> findById(Long id, boolean includeSongs) {
		return findById(id, includeSongs, null);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Playlist> findById(Long id, boolean includeSongs, User user) {
		Optional<Playlist> playlist = playlistRepo.findById(id);
		if (playlist.isPresent()) {
			if (includeSongs) {
				playlist.get().getSongs().size(); // Force eager load
			}
			if (!isMember(user, playlist.get())) {
				playlist.get().setAccessKey(null);
			}
		}
		return playlist;
	}

	@Override
	@Transactional
	public Playlist create(String name, User user, boolean restricted) {
		Playlist playlist = new Playlist().setName(name).setRestricted(restricted);
		if (restricted) {
			playlist.setAccessKey(UUID.randomUUID().toString());
			playlist.getMembers().add(user);
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
	public Playlist addSong(Playlist playlist, Song song, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}
		PlaylistSong playlistSong = new PlaylistSong().setPlaylist(playlist).setSong(song);
		playlist.getSongs().add(playlistSong);
		song.getPlaylists().add(playlistSong);
		song.updateStats();
		return save(playlist);
	}

	@Override
	@Transactional
	public Playlist removeSong(Playlist playlist, Song song, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}
		PlaylistSong playlistSong = new PlaylistSong().setPlaylist(playlist).setSong(song);
		playlist.getSongs().remove(playlistSong);
		song.getPlaylists().remove(playlistSong);
		song.updateStats();
		return save(playlist);
	}

	@Override
	@Transactional
	public Playlist addUser(Playlist playlist, User user, String accessKey) {
		if (playlist.getRestricted() && playlist.getAccessKey() != null) {
			if (playlist.getAccessKey().equals(accessKey)) {
				if (!playlist.getMembers().contains(user)) {
					playlist.getMembers().add(user);
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
	public void delete(Playlist playlist, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}
		playlistRepo.delete(playlist);
	}

	@Override
	public boolean isMember(User user, Playlist playlist) {
		if (playlist == null) {
			return false;
		} else if (user == null) {
			return true;
		} else if (!playlist.getRestricted()) {
			return true;
		} else {
			return playlist.getMembers() != null && playlist.getMembers().contains(user);
		}
	}

}
