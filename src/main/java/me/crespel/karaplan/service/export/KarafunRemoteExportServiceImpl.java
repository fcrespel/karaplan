package me.crespel.karaplan.service.export;

import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import me.crespel.karaplan.config.KarafunRemoteConfig.KarafunRemoteProperties;
import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.service.ExportService;

@Service("karafunRemoteExport")
public class KarafunRemoteExportServiceImpl implements ExportService {

	private static final Pattern remoteTargetPattern = Pattern.compile("\\d+");
	private static final Pattern remoteDisconnectedPattern = Pattern.compile("reactivate the remote control feature");
	private static final Pattern remoteV2UrlPattern = Pattern.compile("\"kcs_url\":\"([^\"]+)\"");

	private final KarafunRemoteProperties properties;
	private final RestTemplate restTemplate;
	private final ExportService karafunRemoteV1ExportService;
	private final ExportService karafunRemoteV2ExportService;

	public KarafunRemoteExportServiceImpl(KarafunRemoteProperties properties, RestTemplateBuilder restTemplateBuilder, @Qualifier("karafunRemoteV1Export") ExportService karafunRemoteV1ExportService, @Qualifier("karafunRemoteV2Export") ExportService karafunRemoteV2ExportService) {
		this.properties = properties;
		this.restTemplate = restTemplateBuilder
				.connectTimeout(Duration.ofMillis(properties.getConnectTimeout()))
				.readTimeout(Duration.ofMillis(properties.getReadTimeout()))
				.defaultHeader(HttpHeaders.USER_AGENT, properties.getUserAgent())
				.build();
		this.karafunRemoteV1ExportService = karafunRemoteV1ExportService;
		this.karafunRemoteV2ExportService = karafunRemoteV2ExportService;
	}

	@Override
	public void exportPlaylist(Playlist playlist, String target) {
		if (!remoteTargetPattern.matcher(target).matches()) {
			throw new BusinessException("Invalid KaraFun Remote target, must be numeric");
		}
		if (playlist.getSongs() != null && !playlist.getSongs().isEmpty()) {
			// Retrieve remote page content
			String remotePage;
			UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(properties.getEndpoint()).path(target);
			try {
				remotePage = restTemplate.getForObject(builder.toUriString(), String.class);
				if (remoteDisconnectedPattern.matcher(remotePage).find()) {
					throw new BusinessException("Remote #" + target + " is not reachable, please check KaraFun application");
				}
			} catch (RestClientException e) {
				throw new TechnicalException("Failed to retrieve KaraFun Remote page, please try again");
			}

			// Determine remote version
			Matcher remoteV2UrlMatcher = remoteV2UrlPattern.matcher(remotePage);
			if (remoteV2UrlMatcher.find()) {
				String remoteV2Url = remoteV2UrlMatcher.group(1).replace("\\/", "/");
				karafunRemoteV2ExportService.exportPlaylist(playlist, remoteV2Url);
			} else {
				karafunRemoteV1ExportService.exportPlaylist(playlist, target);
			}
		}
	}

}
