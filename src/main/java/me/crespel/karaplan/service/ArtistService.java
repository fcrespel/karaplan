package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.Artist;

public interface ArtistService {

	Set<Artist> findAll();

	Set<Artist> findAll(Pageable pageable);

	Optional<Artist> findById(Long id);

	Optional<Artist> findByCatalogId(Long catalogId);

	Artist save(Artist artist);

}
