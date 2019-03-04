package me.crespel.karaplan.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.service.CatalogService;

@Primary
@Service("compositeCatalog")
public class CompositeCatalogServiceImpl implements CatalogService {

	@Autowired
	@Qualifier("karafunCatalog")
	private CatalogService karafunCatalog;
	
	@Autowired
	@Qualifier("kvCatalog")
	private CatalogService kvCatalog;

	@Override
	public CatalogSong getSongInfo(long songId) {
		return karafunCatalog.getSongInfo(songId);
	}

	@Override
	public CatalogSongList getSongList(String filter, Integer limit, Integer offset) {
		return kvCatalog.getSongList(filter, limit, offset);
	}

}
