package me.crespel.karaplan.service.impl;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.client.WebSocketConnectionManager;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.service.ExportService;

@Slf4j
@Service("karafunRemoteV2Export")
public class KarafunRemoteV2ExportServiceImpl implements ExportService {

	protected final Pattern remoteTargetPattern = Pattern.compile("wss://.*");

	@Override
	public void exportPlaylist(Playlist playlist, String target) {
		if (!remoteTargetPattern.matcher(target).matches()) {
			throw new BusinessException("Invalid KaraFun Remote V2 target, must be a WebSocket URL");
		}
		if (playlist.getSongs() != null && !playlist.getSongs().isEmpty()) {
			CompletableFuture<Void> completable = new CompletableFuture<>();
			List<Long> songIds = playlist.getSongs().stream().map(it -> it.getSong().getCatalogId()).collect(Collectors.toList());
			WebSocketConnectionManager wsConn = new WebSocketConnectionManager(new StandardWebSocketClient(), new KarafunWebSocketHandler(songIds, completable), URI.create(target));
			try {
				wsConn.setSubProtocols(Arrays.asList("kcpj~v2+emuping"));
				wsConn.start();
				completable.get(30, TimeUnit.SECONDS);
			} catch (Throwable e) {
				if (e instanceof ExecutionException) {
					e = e.getCause();
				}
				throw new TechnicalException("Failed to export playlist to KaraFun Remote V2: " + e.getMessage(), e);
			} finally {
				wsConn.stop();
			}
		}
	}

	@RequiredArgsConstructor
	public static class KarafunWebSocketHandler extends TextWebSocketHandler {
		private final ObjectMapper mapper = new ObjectMapper();
		private final List<Long> songIds;
		private final CompletableFuture<Void> completable;
		private int index = 0;

		@Override
		public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
			log.error("WebSocket transport error: " + exception.getMessage(), exception);
			completable.completeExceptionally(exception);
		}

		@Override
		protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
			KarafunWebSocketMessage msg = mapper.readValue(message.getPayload(), KarafunWebSocketMessage.class);
			log.debug("Received message: " + msg);
			KarafunWebSocketMessage resp = handleKarafunMessage(msg);
			if (resp != null) {
				log.debug("Sending message: " + resp);
				session.sendMessage(new TextMessage(mapper.writeValueAsString(resp)));
			}
		}

		@SuppressWarnings("unchecked")
		protected KarafunWebSocketMessage handleKarafunMessage(KarafunWebSocketMessage message) {
			switch (message.getType()) {
				case "core.AuthenticatedEvent":
					return buildUpdateUsernameMessage(1, "KaraPlan " + UUID.randomUUID().toString());
				case "core.PingRequest":
					return new KarafunWebSocketMessage().setId(message.getId()).setType("core.PingResponse");
				case "remote.PermissionsUpdateEvent":
					Object perms = message.getPayload().get("permissions");
					if (perms instanceof Map) {
						Object addToQueue = ((Map<String, Object>) perms).get("addToQueue");
						if (!Boolean.TRUE.equals(addToQueue)) {
							completable.completeExceptionally(new BusinessException("Missing 'Add to queue' permission on KaraFun remote, please enable it"));
						} else {
							// Add first song
							return buildAddToQueueMessage(index, songIds.get(index++));
						}
					}
					break;
				case "remote.AddToQueueResponse":
					if (index < songIds.size()) {
						// Add next song
						return buildAddToQueueMessage(index, songIds.get(index++));
					} else {
						log.debug("Finished adding songs to queue");
						completable.complete(null);
					}
					break;
			}
			return null;
		}

		protected KarafunWebSocketMessage buildUpdateUsernameMessage(int index, String username) {
			KarafunWebSocketMessage message = new KarafunWebSocketMessage().setId(index + 1).setType("remote.UpdateUsernameRequest");
			message.getPayload().put("username", username);
			return message;
		}

		protected KarafunWebSocketMessage buildAddToQueueMessage(int index, long songId) {
			KarafunWebSocketMessage message = new KarafunWebSocketMessage().setId(index + 1).setType("remote.AddToQueueRequest");
			Map<String, Object> song = new HashMap<>();
			song.put("type", 1);
			song.put("id", songId);
			message.getPayload().put("song", song);
			return message;
		}
	}

	@Data
	@Accessors(chain = true)
	public static class KarafunWebSocketMessage {
		private Integer id;
		private String type;
		private Map<String, Object> payload = new HashMap<>();
	}

}
