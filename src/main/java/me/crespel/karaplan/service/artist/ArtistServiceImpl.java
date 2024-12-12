package me.crespel.karaplan.service.artist;

import java.util.Optional;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.ConfigurableConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Artist;
import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.repository.ArtistRepo;
import me.crespel.karaplan.service.ArtistService;
import me.crespel.karaplan.service.CatalogService;

@Service
public class ArtistServiceImpl implements ArtistService {

	private final ArtistRepo artistRepo;
	private final CatalogService catalogService;
	private final ConfigurableConversionService conversionService;

	public ArtistServiceImpl(ArtistRepo artistRepo, CatalogService catalogService) {
		this.artistRepo = artistRepo;
		this.catalogService = catalogService;
		this.conversionService = new DefaultConversionService();
		this.conversionService.addConverter(new CatalogArtistToArtistConverter());
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Artist> findAll() {
		return Sets.newLinkedHashSet(artistRepo.findAll());
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Artist> findAll(Pageable pageable) {
		return Sets.newLinkedHashSet(artistRepo.findAll(pageable));
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Artist> findById(Long id) {
		return artistRepo.findById(id);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Artist> findByCatalogId(Long catalogId) {
		Optional<Artist> artist = artistRepo.findByCatalogId(catalogId);
		if (!artist.isPresent()) {
			artist = Optional.ofNullable(conversionService.convert(catalogService.getArtist(catalogId), Artist.class));
		}
		return artist;
	}

	@Override
	@Transactional
	public Artist save(Artist artist) {
		return artistRepo.save(artist);
	}

	public class CatalogArtistToArtistConverter implements Converter<CatalogArtist, Artist> {

		@Override
		public Artist convert(CatalogArtist source) {
			return new Artist()
					.setCatalogId(source.getId())
					.setName(source.getName());
		}

	}

}
