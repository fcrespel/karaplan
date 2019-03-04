package me.crespel.karaplan.service;

import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongList;

public interface CatalogService {

	CatalogSong getSongInfo(long songId);

	CatalogSongList getSongList(String filter, Integer limit, Integer offset);

}
