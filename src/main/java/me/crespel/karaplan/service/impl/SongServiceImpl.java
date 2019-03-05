package me.crespel.karaplan.service.impl;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.repository.SongRepo;
import me.crespel.karaplan.service.SongService;

@Service
public class SongServiceImpl implements SongService {

	@Autowired
	protected SongRepo songRepo;

	@Override
	public Optional<Song> findById(Long id) {
		return songRepo.findById(id);
	}

	@Override
	public Optional<Song> findByCatalogId(Long catalogId) {
		return songRepo.findByCatalogId(catalogId);
	}

	@Override
	public Set<Song> findAll() {
		return Sets.newLinkedHashSet(songRepo.findAll());
	}

}
