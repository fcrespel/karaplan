package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.Song;

public interface SongRepo extends JpaRepository<Song, Long> {

	Optional<Song> findByCatalogId(Long catalogId);

	Iterable<Song> findAllByCatalogIdIn(Iterable<Long> catalogIds);

}
