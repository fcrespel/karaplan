package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.Song;

public interface PlaylistService {

	Set<Playlist> findAll();

	Set<Playlist> findAll(Pageable pageable);

	Optional<Playlist> findById(Long id);

	Optional<Playlist> findById(Long id, boolean includeSongs);

	Playlist save(Playlist playlist);

	Playlist addSong(Playlist playlist, Song song);

	Playlist removeSong(Playlist playlist, Song song);

	void delete(Long id);

}
