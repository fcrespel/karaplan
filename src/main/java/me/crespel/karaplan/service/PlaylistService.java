package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.PlaylistSortDirection;
import me.crespel.karaplan.model.PlaylistSortType;

public interface PlaylistService {

	Set<Playlist> findAll();

	Set<Playlist> findAll(Pageable pageable);

	Set<Playlist> findAll(Pageable pageable, User user);

	Optional<Playlist> findById(Long id);

	Optional<Playlist> findById(Long id, boolean includeDetails);

	Optional<Playlist> findById(Long id, boolean includeDetails, User user);

	Optional<Playlist> findById(Long id, boolean includeDetails, User user, String accessKey);

	Playlist create(String name, User user);

	Playlist save(Playlist playlist);

	Playlist save(Playlist playlist, User user);

	Playlist addSong(Playlist playlist, Song song, User user);

	Playlist removeSong(Playlist playlist, Song song, User user);

	Playlist addUser(Playlist playlist, User user, String accessKey);

	Playlist removeUser(Playlist playlist, User user);

	Playlist addComment(Playlist playlist, User user, String comment);

	Playlist removeComment(Playlist playlist, long commentId);

	Playlist removeComment(Playlist playlist, User user, long commentId);

	Playlist sort(Playlist playlist, PlaylistSortType sortType, PlaylistSortDirection sortDirection, User user);

	void delete(Playlist playlist, User user);

	boolean isMember(User user, Playlist playlist);

}
