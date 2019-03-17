package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.CatalogSelection;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSongListType;

public interface SongService {

	Set<Song> findAll();

	Set<Song> findAll(Pageable pageable);

	Set<Song> search(CatalogSongListType type, String query, Pageable pageable);

	Set<CatalogSelection> getSelections(CatalogSelectionType type);

	Optional<Song> findById(Long id);

	Optional<Song> findByCatalogId(Long catalogId);

	Song save(Song song);

	Song vote(Song song, User user, int score);

	Song addComment(Song song, User user, String comment);

}
