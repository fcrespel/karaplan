package me.crespel.karaplan.service.impl;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.ConfigurableConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import me.crespel.karaplan.config.KVConfig.KVProperties;
import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.model.kv.KvQuery;
import me.crespel.karaplan.model.kv.KvSong;
import me.crespel.karaplan.model.kv.KvSongList;
import me.crespel.karaplan.model.kv.KvSongResponse;
import me.crespel.karaplan.service.CatalogService;

@Service("kvCatalog")
public class KvCatalogServiceImpl implements CatalogService {

	@Autowired
	private KVProperties properties;

	@Autowired
	private RestTemplate restTemplate;

	protected final ConfigurableConversionService conversionService;

	protected final ObjectMapper jsonMapper = new ObjectMapper();

	public KvCatalogServiceImpl() {
		conversionService = new DefaultConversionService();
		conversionService.addConverter(new KvToCatalogSongConverter());
		conversionService.addConverter(new KvToCatalogSongListConverter());
	}

	@Override
	public CatalogSong getSongInfo(long songId) {
		try {
			Map<String, Object> params = new HashMap<>();
			params.put("id", songId);

			KvQuery query = new KvQuery();
			query.setAffiliateId(properties.getAffiliateId());
			query.setFunction("get");
			query.setParameters(params);

			UriComponentsBuilder builder;
				builder = UriComponentsBuilder.fromHttpUrl(properties.getEndpoint())
						.path("/song/")
						.queryParam("query", jsonMapper.writeValueAsString(query));

			KvSongResponse response = restTemplate.getForObject(builder.build().encode().toUri(), KvSongResponse.class);
			return conversionService.convert(response.getSong(), CatalogSong.class);

		} catch (JsonProcessingException | RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	@Override
	public CatalogSongList getSongList(String filter, Integer limit, Integer offset) {
		try {
			Map<String, Object> params = new HashMap<>();
			params.put("query", filter);
			if (limit != null) {
				params.put("limit", limit);
			}
			if (offset != null) {
				params.put("offset", offset);
			}

			KvQuery query = new KvQuery();
			query.setAffiliateId(properties.getAffiliateId());
			query.setFunction("song");
			query.setParameters(params);

			UriComponentsBuilder builder;
				builder = UriComponentsBuilder.fromHttpUrl(properties.getEndpoint())
						.path("/search/")
						.queryParam("query", jsonMapper.writeValueAsString(query));

			KvSongList response = restTemplate.getForObject(builder.build().encode().toUri(), KvSongList.class);
			return conversionService.convert(response, CatalogSongList.class);

		} catch (JsonProcessingException | RestClientException e) {
			throw new TechnicalException(e);
		}
	}

	public class KvToCatalogSongConverter implements Converter<KvSong, CatalogSong> {

		@Override
		public CatalogSong convert(KvSong source) {
			CatalogArtist artist = new CatalogArtist();
			artist.setId(source.getArtistId());

			CatalogSong target = new CatalogSong();
			target.setId(source.getId());
			target.setName(source.getName());
			target.setArtist(artist);
			target.setImg(source.getImgUrl());
			return target;
		}

	}

	public class KvToCatalogSongListConverter implements Converter<KvSongList, CatalogSongList> {

		@Override
		public CatalogSongList convert(KvSongList source) {
			CatalogSongList target = new CatalogSongList();
			target.setCount(source.getLength());
			target.setTotal(source.getTotalLength());
			if (source.getSongs() != null) {
				Set<CatalogSong> targetSongs = new LinkedHashSet<>();
				for (KvSong sourceSong : source.getSongs()) {
					targetSongs.add(conversionService.convert(sourceSong, CatalogSong.class));
				}
				target.setSongs(targetSongs);
			}
			return target;
		}

	}

}
