package me.crespel.karaplan.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import me.crespel.karaplan.domain.Artist;

public interface ArtistRepo extends PagingAndSortingRepository<Artist, Long> {

	Artist findByCatalogId(Long catalogId);

}
