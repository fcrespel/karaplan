package me.crespel.karaplan.service.impl;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.PlaylistSong;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.PlaylistSortDirection;
import me.crespel.karaplan.model.PlaylistSortType;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.repository.PlaylistRepo;
import me.crespel.karaplan.repository.SongRepo;
import me.crespel.karaplan.repository.UserRepo;
import me.crespel.karaplan.service.PlaylistService;

@Service
public class PlaylistServiceImpl implements PlaylistService {

	@Autowired
	protected UserRepo userRepo;

	@Autowired
	protected PlaylistRepo playlistRepo;

	@Autowired
	protected SongRepo songRepo;

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
						playlist.setAccessKey(null).setReadOnly(true);
					}
					if (playlist.getReadOnly() == null) {
						playlist.setReadOnly(false);
					}
					return playlist;
				})
				.collect(Collectors.toCollection(LinkedHashSet::new));
	}

	@Override
	public Set<Playlist> findAllAuthorized(Pageable pageable, User user) {
		return playlistRepo.findAllByRestrictedOrMembersId(false, user.getId(), pageable).stream()
				.map(playlist -> {
					if (playlist.getReadOnly() == null) {
						playlist.setReadOnly(false);
					}
					return playlist;
				})
				.collect(Collectors.toCollection(LinkedHashSet::new));
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
				playlist.get().setAccessKey(null).setReadOnly(true);
			}
			if (playlist.get().getReadOnly() == null) {
				playlist.get().setReadOnly(false);
			}
		}
		return playlist;
	}

	@Override
	@Transactional
	public Playlist create(String name, User user, boolean restricted) {
		Playlist playlist = new Playlist()
				.setName(name)
				.setRestricted(restricted)
				.setReadOnly(false)
				.setAccessKey(UUID.randomUUID().toString());
		playlist.getMembers().add(user);
		return playlistRepo.save(playlist);
	}

	@Override
	@Transactional
	public Playlist save(Playlist playlist) {
		if (playlist.getReadOnly() == null) {
			playlist.setReadOnly(false);
		}
		if (playlist.getAccessKey() == null) {
			playlist.setAccessKey(UUID.randomUUID().toString());
		}
		playlist.updateStats();
		return playlistRepo.save(playlist);
	}

	@Override
	@Transactional
	public Playlist save(Playlist playlist, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}
		if (user != null) {
			if (playlist.getMembers() == null) {
				playlist.setMembers(Sets.newLinkedHashSet());
			}
			if (playlist.getMembers().isEmpty()) {
				playlist.getMembers().add(user);
			}
		}
		return save(playlist);
	}

	@Override
	@Transactional
	public Playlist addSong(Playlist playlist, Song song, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}

		// Import song if necessary 
		if (song.getId() == null) {
			song = songRepo.save(song);
		}

		// Calculate new position
		Integer position = playlist.getSongs().isEmpty() ? 0 : playlist.getSongs().last().getPosition();
		if (position != null) {
			position += 1;
		}

		// Add song
		PlaylistSong playlistSong = new PlaylistSong().setPlaylist(playlist).setSong(song).setPosition(position);
		playlist.getSongs().add(playlistSong);
		song.getPlaylists().add(playlistSong);
		song.updateStats();
		return save(playlist, user);
	}

	@Override
	@Transactional
	public Playlist removeSong(Playlist playlist, Song song, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}

		// Find and remove song
		PlaylistSong playlistSong = new PlaylistSong().setPlaylist(playlist).setSong(song);
		playlist.getSongs().remove(PlaylistSong.findInStream(playlist.getSongs().stream(), playlistSong));
		song.getPlaylists().remove(PlaylistSong.findInStream(song.getPlaylists().stream(), playlistSong));
		song.updateStats();

		// Assign new positions
		setSongPositions(playlist.getSongs());
		return save(playlist, user);
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
	public Playlist sort(Playlist playlist, PlaylistSortType sortType, PlaylistSortDirection sortDirection, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}

		// Sort songs
		List<PlaylistSong> sortedSongs = Lists.newArrayList(playlist.getSongs());
		switch (sortType) {
		case alpha:
			Collections.sort(sortedSongs, PlaylistSong.orderBySongNameComparator);
			break;
		case score:
			Collections.sort(sortedSongs, PlaylistSong.orderBySongScoreComparator);
			break;
		case random:
			Collections.shuffle(sortedSongs);
			break;
		default:
			throw new BusinessException("Invalid sort type " + sortType);
		}

		// Reverse order if necessary
		if (sortDirection == PlaylistSortDirection.desc) {
			Collections.reverse(sortedSongs);
		}

		// Assign new positions
		setSongPositions(sortedSongs);
		return save(playlist, user);
	}

	@Override
	@Transactional
	public void delete(Playlist playlist, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}
		for (PlaylistSong playlistSong : playlist.getSongs()) {
			playlistSong.getSong().getPlaylists().remove(playlistSong);
			playlistSong.getSong().updateStats();
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

	protected void setSongPositions(Collection<PlaylistSong> playlistSongs) {
		int pos = 1;
		for (PlaylistSong playlistSong : playlistSongs) {
			playlistSong.setPosition(pos++);
		}
	}

}
