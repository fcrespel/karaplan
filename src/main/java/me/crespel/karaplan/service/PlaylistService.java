package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import me.crespel.karaplan.domain.Playlist;

public interface PlaylistService {

	public Optional<Playlist> findById(Long id);

	public Set<Playlist> findAll();

}
