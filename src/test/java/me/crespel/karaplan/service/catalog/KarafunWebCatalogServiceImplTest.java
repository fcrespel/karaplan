package me.crespel.karaplan.service.catalog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.hash.Hashing;

import me.crespel.karaplan.config.KarafunWebConfig;
import me.crespel.karaplan.config.KarafunWebConfig.KarafunWebProperties;

@RestClientTest(KarafunWebCatalogServiceImpl.class)
@ContextConfiguration(classes = { KarafunWebCatalogServiceImpl.class, KarafunWebConfig.class })
public class KarafunWebCatalogServiceImplTest extends AbstractCatalogServiceTest<KarafunWebCatalogServiceImpl> {

	@Autowired
	private MockRestServiceServer mockServer;

	@Autowired
	private KarafunWebProperties properties;

	public KarafunWebCatalogServiceImplTest(@Autowired KarafunWebCatalogServiceImpl catalogService) {
		super(catalogService);
		this.testGetArtistEnabled = false;
		this.testGetSongFileListEnabled = false;
	}

	@BeforeEach
	public void setUp() {
		catalogService.clearSessions();
		addMockResponse("session", "open");
	}

	@Test
	@Override
	public void testGetSong() {
		addMockResponse("song", "info", SONG_ID);
		addMockResponse("style", "list");
		super.testGetSong();
	}

	@Test
	@Override
	public void testGetSongListQuery() {
		addMockResponse("song", "search", ARTIST_NAME);
		super.testGetSongListQuery();
	}

	@Test
	@Override
	public void testGetSongListArtist() {
		addMockResponse("song", "list", "ar_" + ARTIST_ID);
		super.testGetSongListArtist();
	}

	@Test
	@Override
	public void testGetSongListStyles() {
		addMockResponse("song", "list", "st_" + STYLE_ID);
		super.testGetSongListStyles();
	}

	@Test
	@Override
	public void testGetSongListTheme() {
		addMockResponse("song", "list", "pl_" + THEME_ID);
		super.testGetSongListTheme();
	}

	@Test
	@Override
	public void testGetSongListTop() {
		addMockResponse("song", "list", "pl_" + TOP_ID);
		super.testGetSongListTop();
	}

	@Test
	@Override
	public void testGetSongListNews() {
		addMockResponse("song", "list", "pl_" + NEWS_ID);
		super.testGetSongListNews();
	}

	@Test
	@Override
	public void testGetSelectionStyles() {
		addMockResponse("style", "list");
		addMockResponse("session", "getfiles");
		super.testGetSelectionStyles();
	}

	@Test
	@Override
	public void testGetSelectionTheme() {
		addMockResponse("playlist", "list", "theme");
		super.testGetSelectionTheme();
	}

	@Test
	@Override
	public void testGetSelectionTop() {
		addMockResponse("playlist", "list", "top");
		super.testGetSelectionTop();
	}

	@Test
	@Override
	public void testGetSelectionNews() {
		addMockResponse("playlist", "list", "news");
		super.testGetSelectionNews();
	}

	@Test
	@Override
	public void testGetSelectionListStyles() {
		addMockResponse("style", "list");
		addMockResponse("session", "getfiles");
		super.testGetSelectionListStyles();
	}

	@Test
	@Override
	public void testGetSelectionListTheme() {
		addMockResponse("playlist", "list", "theme");
		super.testGetSelectionListTheme();
	}

	@Test
	@Override
	public void testGetSelectionListTop() {
		addMockResponse("playlist", "list", "top");
		super.testGetSelectionListTop();
	}

	@Test
	@Override
	public void testGetSelectionListNews() {
		addMockResponse("playlist", "list", "news");
		super.testGetSelectionListNews();
	}

	private void addMockResponse(String path, String action, Object... id) {
		URI uri = UriComponentsBuilder.fromHttpUrl(properties.getEndpoint())
				.pathSegment(path)
				.pathSegment(action + ".php")
				.build().encode().toUri();
		String name = Stream.concat(Stream.of(path, action), Arrays.stream(id))
				.map(Object::toString)
				.map(String::toLowerCase)
				.collect(Collectors.joining("_"));
		Resource resource = new ClassPathResource("karafunweb/" + name + ".xml", getClass());
		mockServer.expect(requestTo(uri))
				.andExpect(method(HttpMethod.POST))
				.andExpect(this::verifyRequestSignature)
				.andRespond(withSuccess(resource, MediaType.TEXT_XML));
	}

	private void verifyRequestSignature(ClientHttpRequest request) {
		String sig = request.getHeaders().getFirst("X-Request-Signature");
		assertThat(sig).as("X-Request-Signature header must be present").isNotBlank();
		String timestamp = request.getHeaders().getFirst("X-Request-Timestamp");
		assertThat(timestamp).as("X-Request-Timestamp header must be present").isNotBlank();
		String body = ((MockClientHttpRequest) request).getBodyAsString();
		assertThat(body).as("Request body must not be blank").isNotBlank();
		String sk = UriComponentsBuilder.fromUriString("?" + body).build().getQueryParams().getFirst("sk");
		assertThat(sk).as("Session key must be present").isNotBlank();
		String hash = Hashing.sha256()
				.hashString(String.join("|", "kfun-v1.5", request.getURI().toString(), body, timestamp, sk), StandardCharsets.UTF_8)
				.toString();
		assertThat(sig).as("Request signature must be valid").isEqualTo(hash);
	}

}
