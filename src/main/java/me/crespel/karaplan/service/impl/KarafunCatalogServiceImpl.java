package me.crespel.karaplan.service.impl;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.ConfigurableConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.collect.Sets;

import me.crespel.karaplan.config.KarafunConfig.KarafunProperties;
import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSelection;
import me.crespel.karaplan.model.CatalogSelectionList;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongFileList;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.model.CatalogStyle;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.model.karafun.KarafunArtist;
import me.crespel.karaplan.model.karafun.KarafunSelection;
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
		conversionService.addConverter(new KarafunToCatalogPlaylistConverter());
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
	public CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset) {
		try {
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(properties.getEndpoint())
					.path(Integer.toString(properties.getRemoteId()))
					.queryParam("type", "song_list");
			switch (type) {
			case query:
				builder = builder.queryParam("filter", "sc_" + filter);
				break;
			case artist:
				builder = builder.queryParam("filter", "ar_" + filter);
				break;
			case styles:
				builder = builder.queryParam("filter", "st_" + filter);
				break;
			case theme:
			case top:
			case news:
				builder = builder.queryParam("filter", "pl_" + filter);
				break;
			}
			if (limit != null) {
				builder = builder.queryParam("limit", limit);
			}
			if (offset != null) {
				builder = builder.queryParam("offset", offset);
			}

			KarafunSongList songList = restTemplate.getForObject(builder.build().encode().toUri(), KarafunSongList.class);
			return conversionService.convert(songList, CatalogSongList.class).setType(type);

		} catch (RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	@Override
	public CatalogSongFileList getSongFileList(long songId) {
		throw new UnsupportedOperationException();
	}

	@Override
	@SuppressWarnings("unchecked")
	@Cacheable("karafunCatalogCache")
	public CatalogSelectionList getSelectionList(CatalogSelectionType type) {
		try {
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(properties.getEndpoint())
					.path(Integer.toString(properties.getRemoteId()))
					.queryParam("type", type.toString());

			List<KarafunSelection> karafunSelectionList = restTemplate.exchange(builder.build().encode().toUri(), HttpMethod.GET, null, new ParameterizedTypeReference<List<KarafunSelection>>() {}).getBody();
			List<CatalogSelection> catalogSelectionList = (List<CatalogSelection>) conversionService.convert(karafunSelectionList, TypeDescriptor.forObject(karafunSelectionList), TypeDescriptor.collection(List.class, TypeDescriptor.valueOf(CatalogSelection.class)));
			return new CatalogSelectionList().setType(type).setSelections(Sets.newLinkedHashSet(catalogSelectionList));

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

	public class KarafunToCatalogPlaylistConverter implements Converter<KarafunSelection, CatalogSelection> {

		@Override
		public CatalogSelection convert(KarafunSelection source) {
			return new CatalogSelection()
					.setId(source.getId())
					.setName(source.getName())
					.setImg(source.getImg());
		}

	}

}
