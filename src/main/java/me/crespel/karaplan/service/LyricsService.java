package me.crespel.karaplan.service;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.model.SongLyrics;

public interface LyricsService {

	SongLyrics getSongLyrics(Song song);

}
