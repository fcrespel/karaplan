package me.crespel.karaplan.service.impl;

import java.util.LinkedHashSet;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.ConfigurableConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import me.crespel.karaplan.config.KarafunConfig.KarafunProperties;
import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogStyle;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.model.karafun.KarafunArtist;
import me.crespel.karaplan.model.karafun.KarafunSong;
import me.crespel.karaplan.model.karafun.KarafunSongList;
import me.crespel.karaplan.model.karafun.KarafunStyle;
import me.crespel.karaplan.service.CatalogService;

@Service("karafunCatalog")
public class KarafunCatalogServiceImpl implements CatalogService {

	@Autowired
	private KarafunProperties properties;

	@Autowired
	private RestTemplate restTemplate;

	protected final ConfigurableConversionService conversionService;

	public KarafunCatalogServiceImpl() {
		conversionService = new DefaultConversionService();
		conversionService.addConverter(new KarafunToCatalogArtistConverter());
		conversionService.addConverter(new KarafunToCatalogStyleConverter());
		conversionService.addConverter(new KarafunToCatalogSongConverter());
		conversionService.addConverter(new KarafunToCatalogSongListConverter());
	}

	@Override
	public CatalogArtist getArtist(long artistId) {
		throw new UnsupportedOperationException();
	}

	@Override
	@Cacheable("karafunCatalogCache")
	public CatalogSong getSong(long songId) {
		try {
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(properties.getEndpoint())
					.path(Integer.toString(properties.getRemoteId()))
					.queryParam("type", "song_info")
					.queryParam("id", Long.toString(songId));

			KarafunSong song = restTemplate.getForObject(builder.build().encode().toUri(), KarafunSong.class);
			return conversionService.convert(song, CatalogSong.class);

		} catch (RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	@Override
	@Cacheable("karafunCatalogCache")
	public CatalogSongList getSongList(String filter, Integer limit, Long offset) {
		try {
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(properties.getEndpoint())
					.path(Integer.toString(properties.getRemoteId()))
					.queryParam("type", "song_list")
					.queryParam("filter", "sc_" + filter);
			if (limit != null) {
				builder = builder.queryParam("limit", limit);
			}
			if (offset != null) {
				builder = builder.queryParam("offset", offset);
			}

			KarafunSongList songList = restTemplate.getForObject(builder.build().encode().toUri(), KarafunSongList.class);
			return conversionService.convert(songList, CatalogSongList.class);

		} catch (RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	public class KarafunToCatalogArtistConverter implements Converter<KarafunArtist, CatalogArtist> {

		@Override
		public CatalogArtist convert(KarafunArtist source) {
			return new CatalogArtist()
					.setId(source.getId())
					.setName(source.getName());
		}

	}

	public class KarafunToCatalogStyleConverter implements Converter<KarafunStyle, CatalogStyle> {

		@Override
		public CatalogStyle convert(KarafunStyle source) {
			return new CatalogStyle()
					.setId(source.getId())
					.setName(source.getName())
					.setImg(source.getImg());
		}

	}

	public class KarafunToCatalogSongConverter implements Converter<KarafunSong, CatalogSong> {

		@Override
		public CatalogSong convert(KarafunSong source) {
			CatalogSong target = new CatalogSong()
					.setId(source.getId())
					.setName(source.getName())
					.setArtist(conversionService.convert(source.getArtist(), CatalogArtist.class))
					.setDuration(source.getDuration())
					.setYear(source.getYear())
					.setImg(source.getImg())
					.setLyrics(source.getLyrics())
					.setRights(source.getRights());
			if (source.getStyles() != null) {
				target.setStyles(source.getStyles().stream()
						.map(it -> conversionService.convert(it, CatalogStyle.class))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return target;
		}

	}

	public class KarafunToCatalogSongListConverter implements Converter<KarafunSongList, CatalogSongList> {

		@Override
		public CatalogSongList convert(KarafunSongList source) {
			CatalogSongList target = new CatalogSongList()
					.setCount(source.getCount())
					.setTotal(source.getTotal());
			if (source.getSongs() != null) {
				target.setSongs(source.getSongs().stream()
						.map(it -> conversionService.convert(it, CatalogSong.class))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return target;
		}

	}

}
