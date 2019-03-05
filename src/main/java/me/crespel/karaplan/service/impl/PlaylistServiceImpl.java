package me.crespel.karaplan.service.impl;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.repository.PlaylistRepo;
import me.crespel.karaplan.service.PlaylistService;

@Service
public class PlaylistServiceImpl implements PlaylistService {

	@Autowired
	protected PlaylistRepo playlistRepo;

	@Override
	public Optional<Playlist> findById(Long id) {
		return playlistRepo.findById(id);
	}

	@Override
	public Set<Playlist> findAll() {
		return Sets.newLinkedHashSet(playlistRepo.findAll());
	}

}
