package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import me.crespel.karaplan.domain.Song;

public interface SongService {

	public Optional<Song> findById(Long id);

	public Optional<Song> findByCatalogId(Long catalogId);

	public Set<Song> findAll();

}
