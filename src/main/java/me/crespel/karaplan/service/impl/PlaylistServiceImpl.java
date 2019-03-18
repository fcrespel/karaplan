package me.crespel.karaplan.service.impl;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.repository.PlaylistRepo;
import me.crespel.karaplan.service.PlaylistService;

@Service
public class PlaylistServiceImpl implements PlaylistService {

	@Autowired
	protected PlaylistRepo playlistRepo;

	@Override
	public Set<Playlist> findAll() {
		return Sets.newLinkedHashSet(playlistRepo.findAll());
	}

	@Override
	public Set<Playlist> findAll(Pageable pageable) {
		return Sets.newLinkedHashSet(playlistRepo.findAll(pageable));
	}

	@Override
	public Optional<Playlist> findById(Long id) {
		return findById(id, false);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Playlist> findById(Long id, boolean includeSongs) {
		Optional<Playlist> playlist = playlistRepo.findById(id);
		if (playlist.isPresent() && includeSongs) {
			playlist.get().getSongs().size(); // Force eager load
		}
		return playlist;
	}

	@Override
	@Transactional
	public Playlist save(Playlist playlist) {
		return playlistRepo.save(playlist);
	}

	@Override
	@Transactional
	public Playlist addSong(Playlist playlist, Song song) {
		playlist.getSongs().add(song);
		song.getPlaylists().add(playlist);
		return playlistRepo.save(playlist);
	}

	@Override
	@Transactional
	public Playlist removeSong(Playlist playlist, Song song) {
		playlist.getSongs().remove(song);
		song.getPlaylists().remove(playlist);
		return playlistRepo.save(playlist);
	}

	@Override
	@Transactional
	public void delete(Long id) {
		playlistRepo.deleteById(id);
	}

}
