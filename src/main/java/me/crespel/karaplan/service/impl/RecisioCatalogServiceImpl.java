package me.crespel.karaplan.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSelectionList;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongFileList;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.service.CatalogService;

@Primary
@Service("recisioCatalog")
public class RecisioCatalogServiceImpl implements CatalogService {

	@Autowired
	@Qualifier("karafunCatalog")
	protected CatalogService karafunCatalog;

	@Autowired
	@Qualifier("kvCatalog")
	protected CatalogService kvCatalog;

	@Override
	public CatalogArtist getArtist(long artistId) {
		return kvCatalog.getArtist(artistId);
	}

	@Override
	public CatalogSong getSong(long songId) {
		return karafunCatalog.getSong(songId);
	}

	@Override
	public CatalogSongList getSongList(CatalogSongListType type, String filter, Integer limit, Long offset) {
		switch (type) {
		case query:
		case artist:
			return kvCatalog.getSongList(type, filter, limit, offset);
		default:
			return karafunCatalog.getSongList(type, filter, limit, offset);
		}
	}

	@Override
	public CatalogSongFileList getSongFileList(long songId) {
		return kvCatalog.getSongFileList(songId);
	}

	@Override
	public CatalogSelectionList getSelectionList(CatalogSelectionType type) {
		return karafunCatalog.getSelectionList(type);
	}

}
