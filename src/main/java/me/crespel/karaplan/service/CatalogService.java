package me.crespel.karaplan.service;

import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongList;

public interface CatalogService {

	CatalogArtist getArtist(long artistId);

	CatalogSong getSong(long songId);

	CatalogSongList getSongList(String filter, Integer limit, Long offset);

}
