package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.Artist;

public interface ArtistRepo extends JpaRepository<Artist, Long> {

	Optional<Artist> findByCatalogId(Long catalogId);

}
