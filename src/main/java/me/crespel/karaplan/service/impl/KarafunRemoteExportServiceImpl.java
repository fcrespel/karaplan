package me.crespel.karaplan.service.impl;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import me.crespel.karaplan.config.KarafunConfig.KarafunRemoteProperties;
import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.service.ExportService;

@Service("karafunRemoteExport")
public class KarafunRemoteExportServiceImpl implements ExportService {

	@Autowired
	@Qualifier("karafunRemoteV1Export")
	protected ExportService karafunRemoteV1ExportService;

	@Autowired
	@Qualifier("karafunRemoteV2Export")
	protected ExportService karafunRemoteV2ExportService;

	@Autowired
	private KarafunRemoteProperties properties;

	@Autowired
	private RestTemplate restTemplate;

	protected final Pattern remoteTargetPattern = Pattern.compile("[0-9]+");
	protected final Pattern remoteDisconnectedPattern = Pattern.compile("reactivate the remote control feature");
	protected final Pattern remoteV2UrlPattern = Pattern.compile("\"kcs_url\":\"([^\"]+)\"");

	@Override
	public void exportPlaylist(Playlist playlist, String target) {
		if (!remoteTargetPattern.matcher(target).matches()) {
			throw new BusinessException("Invalid KaraFun Remote target, must be numeric");
		}
		if (playlist.getSongs() != null && !playlist.getSongs().isEmpty()) {
			// Retrieve remote page content
			String remotePage;
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(properties.getEndpoint()).path(target);
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
