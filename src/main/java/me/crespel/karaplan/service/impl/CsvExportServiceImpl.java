package me.crespel.karaplan.service.impl;

import java.io.FileWriter;
import java.io.IOException;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.stereotype.Service;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.PlaylistSong;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.service.ExportService;

@Service("csvExport")
public class CsvExportServiceImpl implements ExportService {

	private static final String header[] = {
		"ArtistID",
		"ArtistName",
		"SongID",
		"SongName",
		"Duration",
		"Score",
		"ScoreUp",
		"ScoreDown"
	};

	@Override
	public void exportPlaylist(Playlist playlist, String target) {
		if (playlist.getSongs() != null && !playlist.getSongs().isEmpty()) {
			try (CSVPrinter printer = CSVFormat.DEFAULT.builder().setDelimiter(';').setHeader(header).build().print(new FileWriter(target))) {
				for (PlaylistSong playlistSong : playlist.getSongs()) {
					Song song = playlistSong.getSong();
					printer.printRecord(
							song.getArtist().getCatalogId(),
							song.getArtist().getName(),
							song.getCatalogId(),
							song.getName(),
							song.getDuration(),
							song.getScore(),
							song.getScoreUp(),
							song.getScoreDown()
							);
				}
			} catch (IOException e) {
				throw new TechnicalException(e);
			}
		}
	}

}
