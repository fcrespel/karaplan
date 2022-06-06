package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.Song;

public interface SongRepo extends JpaRepository<Song, Long> {

	Optional<Song> findByCatalogId(Long catalogId);

	Iterable<Song> findAllByCatalogIdIn(Iterable<Long> catalogIds);

	Page<Song> findAllByVotesUserId(Long userId, Pageable pageable);

}
