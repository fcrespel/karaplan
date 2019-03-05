package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.repository.PagingAndSortingRepository;

import me.crespel.karaplan.domain.Song;

public interface SongRepo extends PagingAndSortingRepository<Song, Long> {

	Optional<Song> findByCatalogId(Long catalogId);

}
