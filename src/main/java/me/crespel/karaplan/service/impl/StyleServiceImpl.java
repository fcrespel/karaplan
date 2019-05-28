package me.crespel.karaplan.service.impl;

import java.util.Optional;
import java.util.Set;

import com.google.common.collect.Sets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import me.crespel.karaplan.domain.Style;
import me.crespel.karaplan.repository.StyleRepo;
import me.crespel.karaplan.service.StyleService;

@Service
public class StyleServiceImpl implements StyleService {

	@Autowired
	protected StyleRepo styleRepo;

	@Override
	public Set<Style> findAll() {
		return Sets.newLinkedHashSet(styleRepo.findAll());
	}

	@Override
	public Optional<Style> findById(Long id) {
		return styleRepo.findById(id);
	}

	@Override
	public Optional<Style> findByCatalogId(Long catalogId) {
		return styleRepo.findByCatalogId(catalogId);
	}

	@Override
	@Transactional
	public Style save(Style style) {
		return styleRepo.save(style);
	}

}
