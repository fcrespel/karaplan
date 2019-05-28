package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.Style;

public interface StyleRepo extends JpaRepository<Style, Long> {

	Optional<Style> findByCatalogId(Long catalogId);

}
