package me.crespel.karaplan.service.impl;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import me.crespel.karaplan.config.KvConfig.KvProperties;
import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSelectionList;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongFile;
import me.crespel.karaplan.model.CatalogSongFileList;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.model.kv.KvArtist;
import me.crespel.karaplan.model.kv.KvArtistResponse;
import me.crespel.karaplan.model.kv.KvQuery;
import me.crespel.karaplan.model.kv.KvSong;
import me.crespel.karaplan.model.kv.KvSongFile;
import me.crespel.karaplan.model.kv.KvSongFileList;
import me.crespel.karaplan.model.kv.KvSongList;
import me.crespel.karaplan.model.kv.KvSongResponse;
import me.crespel.karaplan.service.CatalogService;

@Service("kvCatalog")
public class KvCatalogServiceImpl implements CatalogService {

	@Autowired
	private KvProperties properties;

	@Autowired
	private RestTemplate restTemplate;

	protected final ConfigurableConversionService conversionService;

	protected final ObjectMapper jsonMapper = new ObjectMapper();

	public KvCatalogServiceImpl() {
		conversionService = new DefaultConversionService();
		conversionService.addConverter(new KvToCatalogArtistConverter());
		conversionService.addConverter(new KvToCatalogSongConverter());
		conversionService.addConverter(new KvToCatalogSongListConverter());
		conversionService.addConverter(new KvToCatalogSongFileConverter());
		conversionService.addConverter(new KvToCatalogSongFileListConverter());
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
	@Cacheable("kvCatalogCache")
	public CatalogArtist getArtist(long artistId) {
		try {
			KvQuery<KvQuery.ArtistGet> query = new KvQuery<KvQuery.ArtistGet>()
					.setAffiliateId(properties.getAffiliateId())
					.setFunction("get")
					.setParameters(new KvQuery.ArtistGet().setId(artistId));

			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getEndpoint())
					.path("/artist/")
					.queryParam("query", jsonMapper.writeValueAsString(query));

			KvArtistResponse response = restTemplate.getForObject(builder.build().encode().toUri(), KvArtistResponse.class);
			return conversionService.convert(response.getArtist(), CatalogArtist.class);

		} catch (JsonProcessingException | RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	@Override
	@Cacheable("kvCatalogCache")
	public CatalogSong getSong(long songId) {
		try {
			KvQuery<KvQuery.SongGet> query = new KvQuery<KvQuery.SongGet>()
					.setAffiliateId(properties.getAffiliateId())
					.setFunction("get")
					.setParameters(new KvQuery.SongGet().setId(songId));

			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getEndpoint())
					.path("/song/")
					.queryParam("query", jsonMapper.writeValueAsString(query));

			KvSongResponse response = restTemplate.getForObject(builder.build().encode().toUri(), KvSongResponse.class);
			return conversionService.convert(response.getSong(), CatalogSong.class);

		} catch (JsonProcessingException | RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	@Override
	@Cacheable("kvCatalogCache")
	public CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset) {
		return getSongList(type, filter, limit, offset, null);
	}

	@Override
	@Cacheable("kvCatalogCache")
	public CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset, Locale locale) {
		try {
			String path;
			KvQuery<?> query;
			switch (type) {
			case query:
				path = "/search/";
				query = new KvQuery<KvQuery.SearchSong>()
						.setAffiliateId(properties.getAffiliateId())
						.setFunction("song")
						.setParameters(new KvQuery.SearchSong().setQuery(filter).setLimit(limit).setOffset(offset));
				break;
			case artist:
				path = "/song/";
				query = new KvQuery<KvQuery.SongList>()
						.setAffiliateId(properties.getAffiliateId())
						.setFunction("list")
						.setParameters(new KvQuery.SongList().setArtistId(Arrays.asList(Long.valueOf(filter))).setLimit(limit).setOffset(offset));
				break;
			default:
				throw new UnsupportedOperationException("Unsupported song list type '" + type + "'");
			}

			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getEndpoint(locale))
					.path(path)
					.queryParam("query", jsonMapper.writeValueAsString(query));

			KvSongList response = restTemplate.getForObject(builder.build().encode().toUri(), KvSongList.class);
			return conversionService.convert(response, CatalogSongList.class).setType(type);

		} catch (JsonProcessingException | RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	@Override
	@Cacheable("kvCatalogCache")
	public CatalogSongFileList getSongFileList(long songId) {
		try {
			KvQuery<KvQuery.SongFileList> query = new KvQuery<KvQuery.SongFileList>()
					.setAffiliateId(properties.getAffiliateId())
					.setFunction("list")
					.setParameters(new KvQuery.SongFileList().setSongId(songId));

			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getEndpoint())
					.path("/songfile/")
					.queryParam("query", jsonMapper.writeValueAsString(query));

			KvSongFileList response = restTemplate.getForObject(builder.build().encode().toUri(), KvSongFileList.class);
			return conversionService.convert(response, CatalogSongFileList.class);

		} catch (JsonProcessingException | RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	@Override
	public CatalogSelectionList getSelectionList(CatalogSelectionType type) {
		return getSelectionList(null);
	}

	@Override
	public CatalogSelectionList getSelectionList(CatalogSelectionType type, Locale locale) {
		throw new UnsupportedOperationException();
	}

	public class KvToCatalogArtistConverter implements Converter<KvArtist, CatalogArtist> {

		@Override
		public CatalogArtist convert(KvArtist source) {
			return new CatalogArtist()
					.setId(source.getId())
					.setName(source.getName());
		}

	}

	public class KvToCatalogSongConverter implements Converter<KvSong, CatalogSong> {

		@Override
		public CatalogSong convert(KvSong source) {
			return new CatalogSong()
					.setId(source.getId())
					.setName(source.getName())
					.setArtist(new CatalogArtist().setId(source.getArtistId()))
					.setImg(source.getImgUrl());
		}

	}

	public class KvToCatalogSongListConverter implements Converter<KvSongList, CatalogSongList> {

		@Override
		public CatalogSongList convert(KvSongList source) {
			CatalogSongList target = new CatalogSongList()
					.setCount(source.getLength())
					.setTotal(source.getTotalLength());
			if (source.getSongs() != null) {
				target.setSongs(source.getSongs().stream()
						.map(it -> conversionService.convert(it, CatalogSong.class))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return target;
		}

	}

	public class KvToCatalogSongFileConverter implements Converter<KvSongFile, CatalogSongFile> {

		@Override
		public CatalogSongFile convert(KvSongFile source) {
			return new CatalogSongFile()
					.setId(source.getId())
					.setSongId(source.getSongId())
					.setArtistId(source.getArtistId())
					.setPreviewUrl(source.getPreviewUrl())
					.setFormat(source.getFormat())
					.setTrackType(source.getTrackType());
		}

	}

	public class KvToCatalogSongFileListConverter implements Converter<KvSongFileList, CatalogSongFileList> {

		@Override
		public CatalogSongFileList convert(KvSongFileList source) {
			CatalogSongFileList target = new CatalogSongFileList()
					.setLength(source.getLength());
			if (source.getSongfiles() != null) {
				target.setSongFiles(source.getSongfiles().stream()
						.map(it -> conversionService.convert(it, CatalogSongFile.class))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return target;
		}

	}

}
