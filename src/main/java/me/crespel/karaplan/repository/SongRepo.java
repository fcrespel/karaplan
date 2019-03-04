package me.crespel.karaplan.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import me.crespel.karaplan.domain.Song;

public interface SongRepo extends PagingAndSortingRepository<Song, Long> {

	Song findByCatalogId(Long catalogId);

}
