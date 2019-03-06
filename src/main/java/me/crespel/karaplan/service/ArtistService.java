package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import me.crespel.karaplan.domain.Artist;

public interface ArtistService {

	Optional<Artist> findById(Long id);

	Optional<Artist> findByCatalogId(Long catalogId);

	Set<Artist> findAll();

	Artist save(Artist artist);

}
