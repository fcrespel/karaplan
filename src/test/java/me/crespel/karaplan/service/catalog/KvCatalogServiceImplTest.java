package me.crespel.karaplan.service.catalog;

import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import me.crespel.karaplan.config.KvConfig;
import me.crespel.karaplan.config.KvConfig.KvProperties;
import me.crespel.karaplan.model.kv.KvQuery;

@RestClientTest(KvCatalogServiceImpl.class)
@ContextConfiguration(classes = { KvCatalogServiceImpl.class, KvConfig.class })
public class KvCatalogServiceImplTest extends AbstractCatalogServiceTest<KvCatalogServiceImpl> {

	@Autowired
	private MockRestServiceServer mockServer;

	@Autowired
	private KvProperties properties;

	private final ObjectMapper jsonMapper = new ObjectMapper();

	public KvCatalogServiceImplTest(@Autowired KvCatalogServiceImpl catalogService) {
		super(catalogService);
		this.testGetSongListStylesEnabled = false;
		this.testGetSongListThemeEnabled = false;
		this.testGetSongListTopEnabled = false;
		this.testGetSongListNewsEnabled = false;
		this.testGetSelectionEnabled = false;
		this.testGetSelectionListEnabled = false;
	}

	@Test
	@Override
	public void testGetArtist() {
		addMockResponse("artist", "get", new KvQuery.ArtistGet().setId(ARTIST_ID), ARTIST_ID);
		super.testGetArtist();
	}

	@Test
	@Override
	public void testGetSong() {
		addMockResponse("song", "get", new KvQuery.SongGet().setId(SONG_ID), SONG_ID);
		super.testGetSong();
	}

	@Test
	@Override
	public void testGetSongListQuery() {
		addMockResponse("search", "song", new KvQuery.SearchSong().setQuery(ARTIST_NAME).setLimit(LIST_LIMIT).setOffset(LIST_OFFSET), ARTIST_NAME);
		super.testGetSongListQuery();
	}

	@Test
	@Override
	public void testGetSongListArtist() {
		addMockResponse("song", "list", new KvQuery.SongList().setArtistId(Collections.singletonList(ARTIST_ID)).setLimit(LIST_LIMIT).setOffset(LIST_OFFSET), ARTIST_ID);
		super.testGetSongListArtist();
	}

	@Test
	@Override
	public void testGetSongFileList() {
		addMockResponse("songfile", "list", new KvQuery.SongFileList().setSongId(SONG_ID), SONG_ID);
		super.testGetSongFileList();
	}

	private <T> void addMockResponse(String path, String function, T params, Object... id) {
		try {
			KvQuery<T> query = new KvQuery<T>()
					.setAffiliateId(properties.getAffiliateId())
					.setFunction(function)
					.setParameters(params);
			URI uri = UriComponentsBuilder.fromUriString(properties.getEndpoint())
					.path("/" + path + "/")
					.queryParam("query", jsonMapper.writeValueAsString(query))
					.build().encode().toUri();
			String name = Stream.concat(Stream.of(path, function), Arrays.stream(id))
					.map(Object::toString)
					.map(String::toLowerCase)
					.collect(Collectors.joining("_"));
			Resource resource = new ClassPathResource("kv/" + name + ".json", getClass());
			mockServer.expect(requestTo(uri))
					.andExpect(method(HttpMethod.GET))
					.andRespond(withSuccess(resource, MediaType.APPLICATION_JSON));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
