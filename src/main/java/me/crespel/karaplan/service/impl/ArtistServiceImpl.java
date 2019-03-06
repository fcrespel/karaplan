package me.crespel.karaplan.service.impl;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.ConfigurableConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Artist;
import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.repository.ArtistRepo;
import me.crespel.karaplan.service.ArtistService;
import me.crespel.karaplan.service.CatalogService;

@Service
public class ArtistServiceImpl implements ArtistService {

	@Autowired
	protected ArtistRepo artistRepo;

	@Autowired
	protected CatalogService catalogService;

	protected final ConfigurableConversionService conversionService;

	public ArtistServiceImpl() {
		conversionService = new DefaultConversionService();
		conversionService.addConverter(new CatalogArtistToArtistConverter());
	}

	@Override
	public Optional<Artist> findById(Long id) {
		return artistRepo.findById(id);
	}

	@Override
	public Optional<Artist> findByCatalogId(Long catalogId) {
		Optional<Artist> artist = artistRepo.findByCatalogId(catalogId);
		if (!artist.isPresent()) {
			artist = Optional.ofNullable(conversionService.convert(catalogService.getArtist(catalogId), Artist.class));
		}
		return artist;
	}

	@Override
	public Set<Artist> findAll() {
		return Sets.newLinkedHashSet(artistRepo.findAll());
	}

	@Override
	public Artist save(Artist artist) {
		return artistRepo.save(artist);
	}

	public class CatalogArtistToArtistConverter implements Converter<CatalogArtist, Artist> {

		@Override
		public Artist convert(CatalogArtist source) {
			Artist target = new Artist();
			target.setCatalogId(source.getId());
			target.setName(source.getName());
			return target;
		}

	}

}
