package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.User;

public interface PlaylistService {

	Set<Playlist> findAll();

	Set<Playlist> findAll(Pageable pageable);

	Set<Playlist> findAllAuthorized(Pageable pageable, User user);
	
	Optional<Playlist> getPlaylist(Long id, boolean includeSongs, User user);

	Optional<Playlist> findById(Long id);

	Optional<Playlist> findById(Long id, boolean includeSongs);

	Playlist create(String name, User user, boolean restricted);

	Playlist save(Playlist playlist);

	Playlist addSong(Playlist playlist, Song song, User user);

	Playlist removeSong(Playlist playlist, Song song, User user);

	Playlist addUser(Playlist playlist, User user, String accessKey);

	void delete(Playlist playlist, User user);
	
	boolean isMember(User user, Playlist playlist);

}
