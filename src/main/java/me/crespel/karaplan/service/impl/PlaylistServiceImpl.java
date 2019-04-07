package me.crespel.karaplan.service.impl;

import java.util.HashSet;
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
	public void delete(Playlist playlist) {
		playlistRepo.delete(playlist);
	}

	@Override
	public Playlist createPlaylist(String name, String username, boolean restricted) {
		Playlist playlist = new Playlist().setName(name).setRestricted(restricted);
		if(restricted) {
			playlist.setAccessKey(UUID.randomUUID().toString());
			Optional<User> user = userRepo.findByUsername(username);
			if(user.isPresent()) {
				Set<User> newAuthorizedSet = null;
				if(playlist.getAuthorizedUsers() != null) {
					newAuthorizedSet = new HashSet<User>(playlist.getAuthorizedUsers());
				} else {
					newAuthorizedSet = new HashSet<User>();
				}
				newAuthorizedSet.add(user.get());
				playlist.setAuthorizedUsers(newAuthorizedSet);
			}
		}
		return playlistRepo.save(playlist);
	}

	@Override
	public void addUserToPlaylist(Long id, String accessKey, String username) {
		Optional<Playlist> playlist = findById(id);
		if(playlist.isPresent()) {
			Playlist p = playlist.get();
			if(p.getRestricted() && p.getAccessKey() != null && p.getAccessKey().equals(accessKey)) {
				Optional<User> user = userRepo.findByUsername(username);
				if(user.isPresent()) {
					Set<User> newAuthorizedSet = null;
					if(p.getAuthorizedUsers() != null) {
						newAuthorizedSet = new HashSet<User>(p.getAuthorizedUsers());
					} else {
						newAuthorizedSet = new HashSet<User>();
					}
					if(!newAuthorizedSet.contains(user.get())) {
						newAuthorizedSet.add(user.get());
						p.setAuthorizedUsers(newAuthorizedSet);
						playlistRepo.save(p);						
					}
				}
			}
		}
	}

	@Override
	public Set<Playlist> getAuthorizedPlaylists(Pageable pageable, String username) {
		Optional<User> user = userRepo.findByUsername(username);
		if(user.isPresent()) {
			return Sets.newLinkedHashSet(playlistRepo.findAllByRestrictedOrAuthorizedUsersId(false, user.get().getId()));
		}
		return Sets.newLinkedHashSet(playlistRepo.findAllByRestricted(false));
	}

}
