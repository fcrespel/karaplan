package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.SongComment;
import me.crespel.karaplan.domain.SongVote;
import me.crespel.karaplan.domain.User;

public interface SongService {

	Set<Song> findAll();

	Set<Song> findAll(Pageable pageable);

	Set<Song> search(String query, Pageable pageable);

	Optional<Song> findById(Long id);

	Optional<Song> findByCatalogId(Long catalogId);

	Song save(Song song);

	SongComment addComment(Song song, User user, String comment);

	SongVote vote(Song song, User user, int score);

}
