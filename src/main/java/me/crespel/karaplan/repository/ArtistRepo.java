package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.repository.PagingAndSortingRepository;

import me.crespel.karaplan.domain.Artist;

public interface ArtistRepo extends PagingAndSortingRepository<Artist, Long> {

	Optional<Artist> findByCatalogId(Long catalogId);

}
