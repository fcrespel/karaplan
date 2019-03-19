package me.crespel.karaplan.service;

import me.crespel.karaplan.domain.Playlist;

public interface ExportService {

	void exportPlaylist(Playlist playlist, String target);

}
