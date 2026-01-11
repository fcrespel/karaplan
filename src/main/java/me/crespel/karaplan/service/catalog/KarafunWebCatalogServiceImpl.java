package me.crespel.karaplan.service.catalog;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.ConfigurableConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.hash.Hashing;

import lombok.extern.slf4j.Slf4j;
import me.crespel.karaplan.config.KarafunWebConfig.KarafunWebProperties;
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
import me.crespel.karaplan.model.karafunweb.KarafunWebArtist;
import me.crespel.karaplan.model.karafunweb.KarafunWebFile;
import me.crespel.karaplan.model.karafunweb.KarafunWebFileResponse;
import me.crespel.karaplan.model.karafunweb.KarafunWebPlaylist;
import me.crespel.karaplan.model.karafunweb.KarafunWebPlaylistList;
import me.crespel.karaplan.model.karafunweb.KarafunWebPlaylistListResponse;
import me.crespel.karaplan.model.karafunweb.KarafunWebResponse;
import me.crespel.karaplan.model.karafunweb.KarafunWebSession;
import me.crespel.karaplan.model.karafunweb.KarafunWebSessionResponse;
import me.crespel.karaplan.model.karafunweb.KarafunWebSong;
import me.crespel.karaplan.model.karafunweb.KarafunWebSongList;
import me.crespel.karaplan.model.karafunweb.KarafunWebSongListResponse;
import me.crespel.karaplan.model.karafunweb.KarafunWebSongResponse;
import me.crespel.karaplan.model.karafunweb.KarafunWebStyle;
import me.crespel.karaplan.model.karafunweb.KarafunWebStyleList;
import me.crespel.karaplan.model.karafunweb.KarafunWebStyleListResponse;
import me.crespel.karaplan.service.CatalogService;

@Slf4j
@Service("karafunWebCatalog")
@CacheConfig(cacheNames = "karafunWebCatalogCache")
public class KarafunWebCatalogServiceImpl implements CatalogService {

	private final KarafunWebProperties properties;
	private final RestClient restClient;
	private final ConfigurableConversionService conversionService;
	private final Map<String, KarafunWebSession> sessions = new ConcurrentHashMap<>();

	public KarafunWebCatalogServiceImpl(KarafunWebProperties properties, RestClient.Builder restClientBuilder) {
		this.properties = properties;
		this.restClient = restClientBuilder
				.defaultHeader(HttpHeaders.USER_AGENT, properties.getUserAgent())
				.build();
		this.conversionService = new DefaultConversionService();
		this.conversionService.addConverter(new MultiValueMapToStringConverter());
		this.conversionService.addConverter(new KarafunToCatalogArtistConverter());
		this.conversionService.addConverter(new KarafunToCatalogStyleConverter());
		this.conversionService.addConverter(new KarafunToCatalogSongConverter());
		this.conversionService.addConverter(new KarafunToCatalogSongListConverter());
		this.conversionService.addConverter(new KarafunFileToCatalogSelectionConverter());
		this.conversionService.addConverter(new KarafunFileToCatalogSelectionListConverter());
		this.conversionService.addConverter(new KarafunStyleToCatalogSelectionConverter());
		this.conversionService.addConverter(new KarafunStyleToCatalogSelectionListConverter());
		this.conversionService.addConverter(new KarafunPlaylistToCatalogSelectionConverter());
		this.conversionService.addConverter(new KarafunPlaylistToCatalogSelectionListConverter());
	}

	private String getEndpoint(Locale locale) {
		String endpoint = null;
		if (locale != null) {
			endpoint = properties.getEndpointForLocale().get(locale.getLanguage());
		}
		if (endpoint == null) {
			endpoint = properties.getEndpoint();
		}
		return endpoint;
	}

	private KarafunWebSession getSession(Locale locale) {
		String sessionKey = locale != null ? locale.getLanguage() : "";
		KarafunWebSession session = sessions.computeIfAbsent(sessionKey, k -> new KarafunWebSession(locale));
		if (!session.isValid()) {
			Map<String, Object> sessionParams = new HashMap<>();
			sessionParams.put("protocol", properties.getProtocol());
			sessionParams.put("client", properties.getClientId());
			sessionParams.put("client_version", properties.getClientVersion());
			sessionParams.put("login", "");
			sessionParams.put("pwd", "");
			sessionParams.put("key", properties.getKey());

			KarafunWebSessionResponse sessionResponse = callApi(session, "session", "open", sessionParams, KarafunWebSessionResponse.class);
			session = sessionResponse.getSession().setLocale(locale);
			if (!session.isValid()) {
				throw new TechnicalException("Invalid KaraFun Web session");
			}
			log.debug("New KaraFun Web session: {}", session);
			sessions.put(sessionKey, session);
		}
		return session;
	}

	protected void clearSessions() {
		sessions.clear();
	}

	private <T extends KarafunWebResponse> T callApi(KarafunWebSession session, String resource, String action, Map<String, Object> params, Class<T> responseType) {
		try {
			// Build URI
			URI uri = UriComponentsBuilder.fromUriString(getEndpoint(session.getLocale()))
					.pathSegment(resource)
					.pathSegment(action + ".php")
					.build().encode().toUri();

			// Build body
			MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
			for (Entry<String, Object> param : params.entrySet()) {
				body.add(param.getKey(), param.getValue());
			}
			body.add("sk", session.getSessionKey());

			// Build headers
			String timestamp = Long.toString(System.currentTimeMillis() / 1000L);
			String bodyString = conversionService.convert(body, String.class);
			String signature = Hashing.sha256().hashString(String.join("|", "kfun-v1.5", uri.toString(), bodyString, timestamp, session.getSessionKey()), StandardCharsets.UTF_8).toString();

			// Call API
			if (log.isTraceEnabled()) {
				log.trace("KaraFun Web API request: {}?{}", uri, bodyString);
			}
			T response = restClient.post()
					.uri(uri)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED)
					.header("X-Request-Timestamp", timestamp)
					.header("X-Request-Signature", signature)
					.body(body)
					.retrieve()
					.body(responseType);
			if (log.isTraceEnabled()) {
				log.trace("KaraFun Web API response: {}", response);
			}

			// Check error
			if (response.isError()) {
				log.warn("KaraFun Web API error: {}", response);
				if (response.shouldRestart() || response.shouldDisconnect()) {
					log.info("Resetting KaraFun Web session for locale: {}", session.getLocale());
					session.reset();
					throw new TechnicalException("KaraFun Web technical error (" + response.getError() + "): " + response.getMessage());
				} else {
					throw new BusinessException("KaraFun Web functional error (" + response.getError() + "): " + response.getMessage());
				}
			} else {
				return response;
			}

		} catch (RestClientException e) {
			throw new TechnicalException("KaraFun Web technical error: " + e.getMessage(), e);
		}
	}

	private <T extends KarafunWebResponse> T callApi(Locale locale, String resource, String action, Map<String, Object> params, Class<T> responseType) {
		KarafunWebSession session = getSession(locale);
		try {
			return callApi(session, resource, action, params, responseType);
		} catch (TechnicalException e) {
			if (!session.isValid()) {
				// Refresh session and retry immediately
				session = getSession(locale);
				return callApi(session, resource, action, params, responseType);
			} else {
				throw e;
			}
		}
	}

	@Override
	public CatalogArtist getArtist(long artistId) {
		throw new UnsupportedOperationException();
	}

	@Override
	@Cacheable
	public CatalogSong getSong(long songId) {
		return getSong(songId, null);
	}

	@Override
	@Cacheable
	public CatalogSong getSong(long songId, Locale locale) {
		KarafunWebSongResponse songResponse = callApi(locale, "song", "info", Collections.singletonMap("song", songId), KarafunWebSongResponse.class);
		if (songResponse.getSong() == null) {
			throw new BusinessException("This song is not available for Karaoke");
		} else {
			CatalogSong song = conversionService.convert(songResponse.getSong(), CatalogSong.class);
			if (song.getStyles() != null && !song.getStyles().isEmpty()) {
				// Load style names
				KarafunWebStyleListResponse styleListResponse = callApi(locale, "style", "list", Collections.singletonMap("no_favorite", 1), KarafunWebStyleListResponse.class);
				if (styleListResponse.getStyles() != null && styleListResponse.getStyles().getStyles() != null) {
					// Convert style list to map
					Map<Long, CatalogStyle> styleMap = styleListResponse.getStyles().getStyles().stream()
							.map(it -> conversionService.convert(it, CatalogStyle.class))
							.collect(Collectors.toMap(CatalogStyle::getId, Function.identity()));
					// Map style ID to full style
					song.setStyles(song.getStyles().stream()
							.map(it -> mergeCatalogStyles(it, styleMap.get(it.getId())))
							.collect(Collectors.toCollection(LinkedHashSet::new)));
				}
			}
			return song;
		}
	}

	@Override
	@Cacheable
	public CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset) {
		return getSongList(type, filter, limit, offset, null);
	}

	@Override
	@Cacheable
	public CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset, Locale locale) {
		String action = "list";
		Map<String, Object> params = new HashMap<>();
		params.put("offset", offset != null ? offset : 0);
		params.put("limit", limit != null ? limit : 20);
		switch (type) {
		case query:
			action = "search";
			params.put("query", filter);
			break;
		case artist:
			params.put("filter", "ar_" + filter);
			break;
		case styles:
			params.put("filter", "st_" + filter);
			break;
		case theme:
		case top:
		case news:
			params.put("filter", "pl_" + filter);
			break;
		}
		KarafunWebSongListResponse songListResponse = callApi(locale, "song", action, params, KarafunWebSongListResponse.class);
		return conversionService.convert(songListResponse.getList(), CatalogSongList.class).setType(type);
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
	@Cacheable
	public CatalogSelection getSelection(CatalogSelectionType type, Long selectionId) {
		return getSelection(type, selectionId, null);
	}

	@Override
	@Cacheable
	public CatalogSelection getSelection(CatalogSelectionType type, Long selectionId, Locale locale) {
		CatalogSelectionList list = getSelectionList(type, locale);
		Optional<CatalogSelection> selection = list.getSelections().stream().filter(it -> selectionId.equals(it.getId())).findFirst();
		return selection.orElseThrow(() -> new BusinessException("Invalid selection ID"));
	}

	@Override
	@Cacheable
	public CatalogSelectionList getSelectionList(CatalogSelectionType type) {
		return getSelectionList(type, null);
	}

	@Override
	@Cacheable
	public CatalogSelectionList getSelectionList(CatalogSelectionType type, Locale locale) {
		if (CatalogSelectionType.styles.equals(type)) {
			// Get styles without images
			KarafunWebStyleListResponse styleListResponse = callApi(locale, "style", "list", Collections.singletonMap("no_favorite", 1), KarafunWebStyleListResponse.class);
			CatalogSelectionList catalogSelectionList1 = conversionService.convert(styleListResponse.getStyles(), CatalogSelectionList.class);

			// Get styles without names
			KarafunWebFileResponse fileResponse = callApi(locale, "session", "getfiles", Collections.singletonMap("imgformat", "sq200"), KarafunWebFileResponse.class);
			CatalogSelectionList catalogSelectionList2 = conversionService.convert(fileResponse, CatalogSelectionList.class);

			// Merge results
			return new CatalogSelectionList().setType(type).setSelections(new LinkedHashSet<>(Stream
					.of(catalogSelectionList1.getSelections(), catalogSelectionList2.getSelections())
					.flatMap(Collection::stream)
					.collect(Collectors.toMap(CatalogSelection::getId, Function.identity(), this::mergeCatalogSelections, LinkedHashMap::new))
					.values()));

		} else {
			Map<String, Object> params = new HashMap<>();
			params.put("limit", 200);
			switch (type) {
			case theme:
				params.put("type", "theme");
				break;
			case top:
				params.put("cat", "popularity");
				break;
			case news:
				params.put("cat", "news");
				break;
			}
			KarafunWebPlaylistListResponse playlistListResponse = callApi(locale, "playlist", "list", params, KarafunWebPlaylistListResponse.class);
			return conversionService.convert(playlistListResponse.getPlaylists(), CatalogSelectionList.class).setType(type);
		}
	}

	private CatalogSelection mergeCatalogSelections(CatalogSelection selection1, CatalogSelection selection2) {
		if (selection1 != null) {
			if (selection2 != null) {
				if (selection1.getName() == null)
					selection1.setName(selection2.getName());
				if (selection1.getImg() == null)
					selection1.setImg(selection2.getImg());
				return selection1;
			} else {
				return selection1;
			}
		} else if (selection2 != null) {
			return selection2;
		} else {
			return null;
		}
	}

	private CatalogStyle mergeCatalogStyles(CatalogStyle style1, CatalogStyle style2) {
		if (style1 != null) {
			if (style2 != null) {
				if (style1.getName() == null)
					style1.setName(style2.getName());
				if (style1.getImg() == null)
					style1.setImg(style2.getImg());
				return style1;
			} else {
				return style1;
			}
		} else if (style2 != null) {
			return style2;
		} else {
			return null;
		}
	}

	public class MultiValueMapToStringConverter implements Converter<MultiValueMap<String, Object>, String> {

		@Override
		public String convert(MultiValueMap<String, Object> source) {
			StringBuilder sb = new StringBuilder();
			source.forEach((name, values) -> {
				values.forEach(value -> {
					if (sb.length() != 0) {
						sb.append('&');
					}
					sb.append(URLEncoder.encode(name, StandardCharsets.UTF_8));
					if (value != null) {
						sb.append('=');
						sb.append(URLEncoder.encode(String.valueOf(value), StandardCharsets.UTF_8));
					}
				});
			});
			return sb.toString();
		}

	}

	public class KarafunToCatalogArtistConverter implements Converter<KarafunWebArtist, CatalogArtist> {

		@Override
		public CatalogArtist convert(KarafunWebArtist source) {
			return new CatalogArtist()
					.setId(source.getId())
					.setName(source.getName());
		}

	}

	public class KarafunToCatalogStyleConverter implements Converter<KarafunWebStyle, CatalogStyle> {

		@Override
		public CatalogStyle convert(KarafunWebStyle source) {
			return new CatalogStyle()
					.setId(Long.parseLong(source.getFilter().replaceFirst("^st_", "")))
					.setName(source.getName());
		}

	}

	public class KarafunToCatalogSongConverter implements Converter<KarafunWebSong, CatalogSong> {

		@Override
		public CatalogSong convert(KarafunWebSong source) {
			CatalogSong target = new CatalogSong()
					.setId(source.getId())
					.setName(source.getTitle())
					.setArtist(conversionService.convert(source.getArtist(), CatalogArtist.class))
					.setDuration(source.getLength())
					.setYear(source.getYear())
					.setImg(source.getImagePath());
			if (source.getLegal() != null) {
				target.setRights(source.getLegal().stream()
						.map(it -> it.getValue())
						.collect(Collectors.joining(" / ")));
			}
			if (source.getStyles() != null) {
				target.setStyles(Arrays.asList(source.getStyles().split(",")).stream()
						.map(it -> new CatalogStyle().setId(Long.parseLong(it)))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return target;
		}

	}

	public class KarafunToCatalogSongListConverter implements Converter<KarafunWebSongList, CatalogSongList> {

		@Override
		public CatalogSongList convert(KarafunWebSongList source) {
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

	public class KarafunFileToCatalogSelectionConverter implements Converter<KarafunWebFile, CatalogSelection> {

		@Override
		public CatalogSelection convert(KarafunWebFile source) {
			return new CatalogSelection()
					.setId(Long.parseLong(source.getName()))
					.setImg(source.getLink());
					// No name available
		}

	}

	public class KarafunFileToCatalogSelectionListConverter implements Converter<KarafunWebFileResponse, CatalogSelectionList> {

		@Override
		public CatalogSelectionList convert(KarafunWebFileResponse source) {
			CatalogSelectionList target = new CatalogSelectionList();
			if (source.getFiles() != null) {
				target.setSelections(source.getFiles().stream()
						.filter(it -> "style".equalsIgnoreCase(it.getType()))
						.map(it -> conversionService.convert(it, CatalogSelection.class))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return target;
		}

	}

	public class KarafunStyleToCatalogSelectionConverter implements Converter<KarafunWebStyle, CatalogSelection> {

		@Override
		public CatalogSelection convert(KarafunWebStyle source) {
			return new CatalogSelection()
					.setId(Long.parseLong(source.getFilter().replaceFirst("^st_", "")))
					.setName(source.getName());
					// No picture available
		}

	}

	public class KarafunStyleToCatalogSelectionListConverter implements Converter<KarafunWebStyleList, CatalogSelectionList> {

		@Override
		public CatalogSelectionList convert(KarafunWebStyleList source) {
			CatalogSelectionList target = new CatalogSelectionList();
			if (source.getStyles() != null) {
				target.setSelections(source.getStyles().stream()
						.map(it -> conversionService.convert(it, CatalogSelection.class))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return target;
		}

	}

	public class KarafunPlaylistToCatalogSelectionConverter implements Converter<KarafunWebPlaylist, CatalogSelection> {

		@Override
		public CatalogSelection convert(KarafunWebPlaylist source) {
			return new CatalogSelection()
					.setId(source.getId())
					.setName(source.getTitle())
					.setImg(source.getImage());
		}

	}

	public class KarafunPlaylistToCatalogSelectionListConverter implements Converter<KarafunWebPlaylistList, CatalogSelectionList> {

		@Override
		public CatalogSelectionList convert(KarafunWebPlaylistList source) {
			CatalogSelectionList target = new CatalogSelectionList();
			if (source.getPlaylists() != null) {
				target.setSelections(source.getPlaylists().stream()
						.map(it -> conversionService.convert(it, CatalogSelection.class))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return target;
		}

	}

}
