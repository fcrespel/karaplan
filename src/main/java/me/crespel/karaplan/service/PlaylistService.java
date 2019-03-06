package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import me.crespel.karaplan.domain.Playlist;

public interface PlaylistService {

	Optional<Playlist> findById(Long id);

	Set<Playlist> findAll();

	Playlist save(Playlist playlist);

}
