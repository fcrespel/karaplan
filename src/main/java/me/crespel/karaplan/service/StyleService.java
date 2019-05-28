package me.crespel.karaplan.service;

import java.util.Optional;
import java.util.Set;

import me.crespel.karaplan.domain.Style;

public interface StyleService {

	Set<Style> findAll();

	Optional<Style> findById(Long id);

	Optional<Style> findByCatalogId(Long catalogId);

	Style save(Style style);

}
