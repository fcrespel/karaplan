package me.crespel.karaplan.service;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.CatalogSongListType;

public interface SongService {

	Set<Song> findAll();

	Set<Song> findAll(Pageable pageable);

	Set<Song> search(CatalogSongListType type, String query, Pageable pageable);

	Set<Song> search(CatalogSongListType type, String query, Pageable pageable, Locale locale);

	Optional<Song> findById(Long id);

	Optional<Song> findByCatalogId(Long catalogId);

	Optional<Song> findByCatalogId(Long catalogId, Locale locale);

	Song save(Song song);

	Song vote(Song song, User user, int score);
	
	void deleteUserVotes(User user);

	Song addComment(Song song, User user, String comment);

	Song removeComment(Song song, long commentId);

	Song removeComment(Song song, User user, long commentId);

}
