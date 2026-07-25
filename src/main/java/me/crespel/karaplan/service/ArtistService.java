package me.crespel.karaplan.service;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Pageable;

import me.crespel.karaplan.domain.Artist;

public interface ArtistService {

	Set<Artist> findAll();

	Set<Artist> findAll(Pageable pageable);

	Optional<Artist> findById(Long id);

	Optional<Artist> findByCatalogId(Long catalogId);

	Optional<Artist> findByCatalogId(Long catalogId, Locale locale);

	Artist save(Artist artist);

}
