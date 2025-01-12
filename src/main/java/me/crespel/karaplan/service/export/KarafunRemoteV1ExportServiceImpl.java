package me.crespel.karaplan.service.export;

import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import io.socket.client.Ack;
import io.socket.client.IO;
import io.socket.client.Socket;
import io.socket.emitter.Emitter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.crespel.karaplan.config.KarafunRemoteConfig.KarafunRemoteProperties;
import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.service.ExportService;

@Slf4j
@Service("karafunRemoteV1Export")
public class KarafunRemoteV1ExportServiceImpl implements ExportService {

	private static final String EVENT_AUTHENTICATE = "authenticate";
	private static final String EVENT_PERMISSIONS = "permissions";
	private static final String EVENT_PREFERENCES = "preferences";
	private static final String EVENT_STATUS = "status";
	private static final String EVENT_QUEUE = "queue";
	private static final String EVENT_QUEUE_ADD = "queueAdd";
	private static final Pattern remoteTargetPattern = Pattern.compile("\\d+");

	private final KarafunRemoteProperties properties;

	public KarafunRemoteV1ExportServiceImpl(KarafunRemoteProperties properties) {
		this.properties = properties;
	}

	@Override
	public void exportPlaylist(Playlist playlist, String target) {
		if (!remoteTargetPattern.matcher(target).matches()) {
			throw new BusinessException("Invalid KaraFun Remote V1 target, must be numeric");
		}
		if (playlist.getSongs() != null && !playlist.getSongs().isEmpty()) {
			CompletableFuture<Void> completable = new CompletableFuture<>();
			List<Long> songIds = playlist.getSongs().stream().map(it -> it.getSong().getCatalogId()).collect(Collectors.toList());
			Socket socket = buildSocket(target);
			try {
				socket.on(Socket.EVENT_CONNECT, new ConnectEventListener(socket, target))
						.on(Socket.EVENT_CONNECT_ERROR, new LoggingListener(Socket.EVENT_CONNECT_ERROR))
						.on(Socket.EVENT_CONNECT_TIMEOUT, new LoggingListener(Socket.EVENT_CONNECT_TIMEOUT))
						.on(Socket.EVENT_ERROR, new ErrorEventListener(completable))
						.on(Socket.EVENT_MESSAGE, new LoggingListener(Socket.EVENT_MESSAGE))
						.on(Socket.EVENT_DISCONNECT, new LoggingListener(Socket.EVENT_DISCONNECT))
						.on(EVENT_PERMISSIONS, new PermissionsEventListener(completable))
						.on(EVENT_PREFERENCES, new LoggingListener(EVENT_PREFERENCES))
						.on(EVENT_STATUS, new LoggingListener(EVENT_STATUS))
						.on(EVENT_QUEUE, new QueueEventListener(socket, songIds, completable));
				log.debug("Connecting to Karafun Remote {}", target);
				socket.connect();
				completable.get(30, TimeUnit.SECONDS);
			} catch (Throwable e) {
				if (e instanceof ExecutionException) {
					e = e.getCause();
				}
				throw new TechnicalException("Failed to export playlist to KaraFun Remote V1: " + e.getMessage(), e);
			} finally {
				socket.disconnect();
			}
		}
	}

	private Socket buildSocket(String remoteId) {
		try {
			IO.Options opts = new IO.Options();
			opts.forceNew = true;
			opts.reconnection = false;
			opts.query = "remote=kf" + remoteId;
			return IO.socket(properties.getEndpoint(), opts);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException(e);
		}
	}

	private JSONObject buildAuthenticateEvent(String remoteId) {
		try {
			JSONObject obj = new JSONObject();
			obj.put("login", "KaraPlan");
			obj.put("channel", remoteId);
			obj.put("role", "participant");
			obj.put("app", "karafun");
			obj.put("socket_id", JSONObject.NULL);
			return obj;
		} catch (JSONException e) {
			throw new RuntimeException(e);
		}
	}

	private JSONObject buildQueueAddEvent(Long songId) {
		try {
			JSONObject obj = new JSONObject();
			obj.put("songId", songId);
			obj.put("pos", 99999);
			obj.put("singer", "");
			return obj;
		} catch (JSONException e) {
			throw new RuntimeException(e);
		}
	}

	private void logSendEvent(String eventName, Object... args) {
		log.debug("Sending event {}: {}", eventName, args);
	}

	private void logReceivedEvent(String eventName, Object... args) {
		log.debug("Received event {}: {}", eventName, args);
	}

	private void logReceivedAck(String eventName, Object... args) {
		log.debug("Received ack for {}: {}", eventName, args);
	}

	@RequiredArgsConstructor
	public class LoggingListener implements Emitter.Listener {
		private final String eventName;

		@Override
		public void call(Object... args) {
			logReceivedEvent(eventName, args);
		}
	}

	@RequiredArgsConstructor
	public class LoggingAck implements Ack {
		private final String eventName;

		@Override
		public void call(Object... args) {
			logReceivedAck(eventName, args);
		}
	}

	@RequiredArgsConstructor
	public class ConnectEventListener implements Emitter.Listener {
		private final Socket socket;
		private final String remoteId;

		@Override
		public void call(Object... args) {
			logReceivedEvent(Socket.EVENT_CONNECT, args);
			JSONObject eventData = buildAuthenticateEvent(remoteId);
			logSendEvent(EVENT_AUTHENTICATE, eventData);
			socket.emit(EVENT_AUTHENTICATE, eventData, new LoggingAck(EVENT_AUTHENTICATE));
		}
	}

	@RequiredArgsConstructor
	public class ErrorEventListener implements Emitter.Listener {
		private final CompletableFuture<Void> completable;

		@Override
		public void call(Object... args) {
			logReceivedEvent(Socket.EVENT_ERROR, args);
			completable.completeExceptionally(new RuntimeException("Socket.IO error: " + Arrays.toString(args)));
		}
	}

	@RequiredArgsConstructor
	public class PermissionsEventListener implements Emitter.Listener {
		private final CompletableFuture<Void> completable;

		@Override
		public void call(Object... args) {
			logReceivedEvent(EVENT_PERMISSIONS, args);
			if (args != null && args.length > 0 && !args[0].toString().contains("addToQueue")) {
				completable.completeExceptionally(new BusinessException("Missing 'Add to queue' permission on KaraFun remote, please enable it"));
			}
		}
	}

	@RequiredArgsConstructor
	public class QueueEventListener implements Emitter.Listener {
		private final Socket socket;
		private final List<Long> songIds;
		private final CompletableFuture<Void> completable;
		private int index = 0;

		@Override
		public void call(Object... args) {
			logReceivedEvent(EVENT_QUEUE, args);
			if (index < songIds.size()) {
				JSONObject eventData = buildQueueAddEvent(songIds.get(index++));
				logSendEvent(EVENT_QUEUE_ADD, eventData);
				socket.emit(EVENT_QUEUE_ADD, eventData);
			} else {
				log.debug("Finished adding songs to queue");
				completable.complete(null);
			}
		}
	}

}
