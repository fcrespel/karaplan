package me.crespel.karaplan.service;

import java.util.Locale;

import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSelectionList;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongFileList;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogSongListType;

public interface CatalogService {

	CatalogArtist getArtist(long artistId);

	CatalogSong getSong(long songId);

	CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset);

	CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset, Locale locale);

	CatalogSongFileList getSongFileList(long songId);

	CatalogSelectionList getSelectionList(CatalogSelectionType type);

	CatalogSelectionList getSelectionList(CatalogSelectionType type, Locale locale);

}
