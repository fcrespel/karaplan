package me.crespel.karaplan.service.impl;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.collect.Sets;

import me.crespel.karaplan.config.KarafunConfig.KarafunRemoteProperties;
import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSelection;
import me.crespel.karaplan.model.CatalogSelectionList;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongFileList;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.model.CatalogStyle;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.model.karafunremote.KarafunRemoteArtist;
import me.crespel.karaplan.model.karafunremote.KarafunRemoteSelection;
import me.crespel.karaplan.model.karafunremote.KarafunRemoteSong;
import me.crespel.karaplan.model.karafunremote.KarafunRemoteSongList;
import me.crespel.karaplan.model.karafunremote.KarafunRemoteStyle;
import me.crespel.karaplan.service.CatalogService;

@Service("karafunRemoteCatalog")
public class KarafunRemoteCatalogServiceImpl implements CatalogService {

	@Autowired
	private KarafunRemoteProperties properties;

	@Autowired
	private RestTemplate restTemplate;

	protected final ConfigurableConversionService conversionService;

	public KarafunRemoteCatalogServiceImpl() {
		conversionService = new DefaultConversionService();
		conversionService.addConverter(new KarafunToCatalogArtistConverter());
		conversionService.addConverter(new KarafunToCatalogStyleConverter());
		conversionService.addConverter(new KarafunToCatalogSongConverter());
		conversionService.addConverter(new KarafunToCatalogSongListConverter());
		conversionService.addConverter(new KarafunToCatalogPlaylistConverter());
	}

	protected String getEndpoint() {
		return getEndpoint(null);
	}

	protected String getEndpoint(Locale locale) {
		String endpoint = null;
		if (locale != null) {
			endpoint = properties.getEndpointForLocale().get(locale.getLanguage());
		}
		if (endpoint == null) {
			endpoint = properties.getEndpoint();
		}
		return endpoint;
	}

	@Override
	public CatalogArtist getArtist(long artistId) {
		throw new UnsupportedOperationException();
	}

	@Override
	@Cacheable("karafunRemoteCatalogCache")
	public CatalogSong getSong(long songId) {
		return getSong(songId, null);
	}

	@Override
	@Cacheable("karafunRemoteCatalogCache")
	public CatalogSong getSong(long songId, Locale locale) {
		try {
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getEndpoint(locale))
					.path(Integer.toString(properties.getRemoteId()))
					.queryParam("type", "song_info")
					.queryParam("id", Long.toString(songId));

			KarafunRemoteSong song = restTemplate.getForObject(builder.build().encode().toUri(), KarafunRemoteSong.class);
			return conversionService.convert(song, CatalogSong.class);

		} catch (HttpClientErrorException.Forbidden e) {
			throw new BusinessException("This song is not available for Karaoke");
		} catch (HttpClientErrorException.NotFound e) {
			throw new BusinessException("This song ID does not exist");
		} catch (RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	@Override
	@Cacheable("karafunRemoteCatalogCache")
	public CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset) {
		return getSongList(type, filter, limit, offset, null);
	}

	@Override
	@Cacheable("karafunRemoteCatalogCache")
	public CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset, Locale locale) {
		try {
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getEndpoint(locale))
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

			KarafunRemoteSongList songList = restTemplate.getForObject(builder.build().encode().toUri(), KarafunRemoteSongList.class);
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
	public CatalogSongFileList getSongFileList(long songId, Locale locale) {
		throw new UnsupportedOperationException();
	}

	@Override
	@Cacheable("karafunRemoteCatalogCache")
	public CatalogSelection getSelection(CatalogSelectionType type, Long selectionId) {
		return getSelection(type, selectionId, null);
	}

	@Override
	@Cacheable("karafunRemoteCatalogCache")
	public CatalogSelection getSelection(CatalogSelectionType type, Long selectionId, Locale locale) {
		CatalogSelectionList list = getSelectionList(type, locale);
		Optional<CatalogSelection> selection = list.getSelections().stream().filter(it -> selectionId.equals(it.getId())).findFirst();
		return selection.orElseThrow(() -> new BusinessException("Invalid selection ID"));
	}

	@Override
	@Cacheable("karafunRemoteCatalogCache")
	public CatalogSelectionList getSelectionList(CatalogSelectionType type) {
		return getSelectionList(type, null);
	}

	@Override
	@SuppressWarnings("unchecked")
	@Cacheable("karafunRemoteCatalogCache")
	public CatalogSelectionList getSelectionList(CatalogSelectionType type, Locale locale) {
		try {
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getEndpoint(locale))
					.path(Integer.toString(properties.getRemoteId()))
					.queryParam("type", type.toString());

			List<KarafunRemoteSelection> karafunSelectionList = restTemplate.exchange(builder.build().encode().toUri(), HttpMethod.GET, null, new ParameterizedTypeReference<List<KarafunRemoteSelection>>() {}).getBody();
			List<CatalogSelection> catalogSelectionList = (List<CatalogSelection>) conversionService.convert(karafunSelectionList, TypeDescriptor.forObject(karafunSelectionList), TypeDescriptor.collection(List.class, TypeDescriptor.valueOf(CatalogSelection.class)));
			return new CatalogSelectionList().setType(type).setSelections(Sets.newLinkedHashSet(catalogSelectionList));

		} catch (RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	public class KarafunToCatalogArtistConverter implements Converter<KarafunRemoteArtist, CatalogArtist> {

		@Override
		public CatalogArtist convert(KarafunRemoteArtist source) {
			return new CatalogArtist()
					.setId(source.getId())
					.setName(source.getName());
		}

	}

	public class KarafunToCatalogStyleConverter implements Converter<KarafunRemoteStyle, CatalogStyle> {

		@Override
		public CatalogStyle convert(KarafunRemoteStyle source) {
			return new CatalogStyle()
					.setId(source.getId())
					.setName(source.getName())
					.setImg(source.getImg());
		}

	}

	public class KarafunToCatalogSongConverter implements Converter<KarafunRemoteSong, CatalogSong> {

		@Override
		public CatalogSong convert(KarafunRemoteSong source) {
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

	public class KarafunToCatalogSongListConverter implements Converter<KarafunRemoteSongList, CatalogSongList> {

		@Override
		public CatalogSongList convert(KarafunRemoteSongList source) {
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

	public class KarafunToCatalogPlaylistConverter implements Converter<KarafunRemoteSelection, CatalogSelection> {

		@Override
		public CatalogSelection convert(KarafunRemoteSelection source) {
			return new CatalogSelection()
					.setId(source.getId())
					.setName(source.getName())
					.setImg(source.getImg());
		}

	}

}
