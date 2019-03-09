package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.Playlist;

public interface PlaylistService {

	Set<Playlist> findAll();

	Set<Playlist> findAll(Pageable pageable);

	Optional<Playlist> findById(Long id);

	Playlist save(Playlist playlist);

}
