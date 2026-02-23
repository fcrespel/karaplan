package me.crespel.karaplan.service.playlist;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.PlaylistComment;
import me.crespel.karaplan.domain.PlaylistSong;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.PlaylistSortDirection;
import me.crespel.karaplan.model.PlaylistSortType;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.repository.PlaylistRepo;
import me.crespel.karaplan.repository.SongRepo;
import me.crespel.karaplan.service.PlaylistService;

@Service
public class PlaylistServiceImpl implements PlaylistService {

	private final SongRepo songRepo;
	private final PlaylistRepo playlistRepo;

	public PlaylistServiceImpl(SongRepo songRepo, PlaylistRepo playlistRepo) {
		this.songRepo = songRepo;
		this.playlistRepo = playlistRepo;
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Playlist> findAll() {
		return Sets.newLinkedHashSet(playlistRepo.findAll());
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Playlist> findAll(Pageable pageable) {
		return Sets.newLinkedHashSet(playlistRepo.findAll(pageable));
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Playlist> findAll(User user) {
		return findAll(null, user);
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Playlist> findAll(Pageable pageable, User user) {
		return playlistRepo.findAllByMembersId(user.getId(), pageable).stream()
				.map(playlist -> {
					if (playlist.getReadOnly() == null) {
						playlist.setReadOnly(false);
					}
					return playlist;
				})
				.collect(Collectors.toCollection(LinkedHashSet::new));
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Playlist> findById(Long id) {
		return findById(id, false);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Playlist> findById(Long id, boolean includeDetails) {
		return findById(id, includeDetails, null);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Playlist> findById(Long id, boolean includeDetails, User user) {
		return findById(id, includeDetails, null, null);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Playlist> findById(Long id, boolean includeDetails, User user, String accessKey) {
		Optional<Playlist> playlist = playlistRepo.findById(id);
		if (playlist.isPresent()) {
			Playlist p = playlist.get();
			if (isMember(user, p)) {
				if (p.getReadOnly() == null) {
					p.setReadOnly(false);
				}
			} else if (accessKey != null) {
				if (p.getAccessKey() != null && !p.getAccessKey().equals(accessKey)) {
					throw new BusinessException("Invalid playlist access key");
				}
				p.setReadOnly(true);
			} else {
				throw new BusinessException("User " + user + " is not a member of playlist " + p);
			}
			if (includeDetails) {
				// Force eager load
				p.getSongs().size();
				p.getComments().size();
			}
		}
		return playlist;
	}

	@Override
	@Transactional
	public Playlist create(String name, User user) {
		Playlist playlist = new Playlist().setName(name);
		if (user != null) {
			playlist.getMembers().add(user);
		}
		return save(playlist, user);
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
		return save(playlist);
	}

	@Override
	@Transactional
	public Playlist addSong(Playlist playlist, Song song, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		} else if (Boolean.TRUE.equals(playlist.getReadOnly())) {
			throw new BusinessException("Playlist " + playlist + " is read-only");
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
		} else if (Boolean.TRUE.equals(playlist.getReadOnly())) {
			throw new BusinessException("Playlist " + playlist + " is read-only");
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
		if (playlist.getAccessKey() != null && playlist.getAccessKey().equals(accessKey)) {
			if (!isMember(user, playlist)) {
				playlist.getMembers().add(user);
				return save(playlist);
			}
		} else {
			throw new BusinessException("Invalid playlist access key");
		}
		return playlist;
	}

	@Override
	@Transactional
	public Playlist removeUser(Playlist playlist, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}

		if (user != null) {
			playlist.getMembers().remove(user);
			return save(playlist);
		}

		return playlist;
	}

	@Override
	@Transactional
	public Playlist addComment(Playlist playlist, User user, String comment) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}

		playlist.getComments().add(new PlaylistComment()
				.setPlaylist(playlist)
				.setUser(user)
				.setComment(comment));
		return save(playlist);
	}

	@Override
	@Transactional
	public Playlist removeComment(Playlist playlist, long commentId) {
		return removeComment(playlist, null, commentId);
	}

	@Override
	@Transactional
	public Playlist removeComment(Playlist playlist, User user, long commentId) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		}

		playlist.getComments().removeIf(it -> it.getId() == commentId && (user == null || user.equals(it.getUser())));
		return save(playlist);
	}

	@Override
	@Transactional
	public Playlist sort(Playlist playlist, PlaylistSortType sortType, PlaylistSortDirection sortDirection, User user) {
		if (!isMember(user, playlist)) {
			throw new BusinessException("User " + user + " is not a member of playlist " + playlist);
		} else if (Boolean.TRUE.equals(playlist.getReadOnly())) {
			throw new BusinessException("Playlist " + playlist + " is read-only");
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
		case dateAdded:
			Collections.sort(sortedSongs, PlaylistSong.orderByCreatedDateComparator);
			break;
		case random:
			Collections.shuffle(sortedSongs);
			break;
		case smart:
			Collections.shuffle(sortedSongs);
			sortedSongs = sortByMaxSpacing(sortedSongs);
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
	public Playlist sortCustom(Playlist playlist, List<Long> songIdList, User user) {
		for (int i = 0; i < songIdList.size(); i++) {
			for (PlaylistSong ps : playlist.getSongs()) {
				if (ps.getSong().getId().equals(songIdList.get(i))) {
					ps.setPosition(i + 1);
				}
			}
		}
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
		} else {
			return playlist.getMembers() != null && playlist.getMembers().stream().anyMatch(m -> m.getId().equals(user.getId()));
		}
	}

	private void setSongPositions(Collection<PlaylistSong> playlistSongs) {
		int pos = 1;
		for (PlaylistSong playlistSong : playlistSongs) {
			playlistSong.setPosition(pos++);
		}
	}

	private List<PlaylistSong> sortByMaxSpacing(List<PlaylistSong> songs) {
		if (songs == null || songs.size() <= 1) {
			return songs;
		}
		
		// Create a list of each user songlist, sorted by the size of it
		List<LinkedList<PlaylistSong>> users = songs.stream()
		.collect(Collectors.groupingBy(
			s -> s.getCreatedBy().getId(),
			LinkedHashMap::new,
			Collectors.toCollection(LinkedList::new)))
		.values()
		.stream()
		.sorted((a, b) -> Integer.compare(b.size(), a.size()))
		.toList();
		
		// create empty array the size of the playlist
		PlaylistSong[] result = new PlaylistSong[songs.size()];
		int n = result.length;
		
		// max space between each song of a user
		for (List<PlaylistSong> userSongs : users) {
			int count = userSongs.size();
			
			for (int k = 0; k < count; k++) {
				// for a 40 songs playlist and 10 songs for the user : k * n / count -> k * 40 / 10 -> 0 4 8 12...
				int target = (int) ((long) k * n / count);
				int i = target;

				// while spot is taken, try to take the next one
				while (i < n && result[i] != null) {
					i++;
				}
				// if empty spot is within array size, take it
				if (i < n) {
					result[i] = userSongs.get(k);
				}
			}
		}
		// put array back into List and return result
		return Arrays.asList(result);
	}
}
