package me.crespel.karaplan.service;

import java.util.Locale;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSelection;
import me.crespel.karaplan.model.CatalogSelectionList;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongFileList;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogSongListType;

public abstract class AbstractCatalogServiceIT {

	protected static final Locale DEFAULT_LOCALE = Locale.FRANCE;
	protected static final long SONG_ID = 19237;
	protected static final String SONG_NAME = "Feeling Good";
	protected static final long ARTIST_ID = 3888;
	protected static final String ARTIST_NAME = "Muse";
	protected static final long STYLE_ID = 2;  // Rock
	protected static final long THEME_ID = 94; // Best Of
	protected static final long TOP_ID = 100;  // Global Top
	protected static final long NEWS_ID = 123; // Top Hits

	protected CatalogService catalogService;
	protected Locale locale;
	protected boolean testGetArtistEnabled = true;
	protected boolean testGetSongEnabled = true;
	protected boolean testGetSongListEnabled = true;
	protected boolean testGetSongListQueryEnabled = true;
	protected boolean testGetSongListArtistEnabled = true;
	protected boolean testGetSongListStylesEnabled = true;
	protected boolean testGetSongListThemeEnabled = true;
	protected boolean testGetSongListTopEnabled = true;
	protected boolean testGetSongListNewsEnabled = true;
	protected boolean testGetSongFileListEnabled = true;
	protected boolean testGetSelectionEnabled = true;
	protected boolean testGetSelectionStylesEnabled = true;
	protected boolean testGetSelectionThemeEnabled = true;
	protected boolean testGetSelectionTopEnabled = true;
	protected boolean testGetSelectionNewsEnabled = true;
	protected boolean testGetSelectionListEnabled = true;
	protected boolean testGetSelectionListStylesEnabled = true;
	protected boolean testGetSelectionListThemeEnabled = true;
	protected boolean testGetSelectionListTopEnabled = true;
	protected boolean testGetSelectionListNewsEnabled = true;

	public AbstractCatalogServiceIT(CatalogService catalogService) {
		this(catalogService, DEFAULT_LOCALE);
	}

	public AbstractCatalogServiceIT(CatalogService catalogService, Locale locale) {
		this.catalogService = catalogService;
		this.locale = locale;
	}

	@Test
	public void testGetArtist() {
		Assumptions.assumeTrue(testGetArtistEnabled);
		CatalogArtist artist = catalogService.getArtist(ARTIST_ID);
		Assertions.assertNotNull(artist);
		Assertions.assertEquals(ARTIST_ID, artist.getId());
		Assertions.assertEquals(ARTIST_NAME, artist.getName());
	}

	@Test
	public void testGetSong() {
		Assumptions.assumeTrue(testGetSongEnabled);
		CatalogSong song = catalogService.getSong(SONG_ID, locale);
		Assertions.assertNotNull(song);
		Assertions.assertEquals(SONG_ID, song.getId());
		Assertions.assertEquals(SONG_NAME, song.getName());
		Assertions.assertNotNull(song.getArtist());
		Assertions.assertEquals(ARTIST_ID, song.getArtist().getId());
	}

	@Test
	public void testGetSongListQuery() {
		Assumptions.assumeTrue(testGetSongListEnabled && testGetSongListQueryEnabled);
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.query, ARTIST_NAME, 10, 0L, locale);
		Assertions.assertNotNull(list);
		Assertions.assertTrue(list.getCount() > 0);
		Assertions.assertNotNull(list.getSongs());
		Assertions.assertTrue(list.getSongs().size() > 0);
	}

	@Test
	public void testGetSongListArtist() {
		Assumptions.assumeTrue(testGetSongListEnabled && testGetSongListArtistEnabled);
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.artist, String.valueOf(ARTIST_ID), 10, 0L, locale);
		Assertions.assertNotNull(list);
		Assertions.assertTrue(list.getCount() > 0);
		Assertions.assertNotNull(list.getSongs());
		Assertions.assertTrue(list.getSongs().size() > 0);
	}

	@Test
	public void testGetSongListStyles() {
		Assumptions.assumeTrue(testGetSongListEnabled && testGetSongListStylesEnabled);
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.styles, String.valueOf(STYLE_ID), 10, 0L, locale);
		Assertions.assertNotNull(list);
		Assertions.assertTrue(list.getCount() > 0);
		Assertions.assertNotNull(list.getSongs());
		Assertions.assertTrue(list.getSongs().size() > 0);
	}

	@Test
	public void testGetSongListTheme() {
		Assumptions.assumeTrue(testGetSongListEnabled && testGetSongListThemeEnabled);
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.theme, String.valueOf(THEME_ID), 10, 0L, locale);
		Assertions.assertNotNull(list);
		Assertions.assertTrue(list.getCount() > 0);
		Assertions.assertNotNull(list.getSongs());
		Assertions.assertTrue(list.getSongs().size() > 0);
	}

	@Test
	public void testGetSongListTop() {
		Assumptions.assumeTrue(testGetSongListEnabled && testGetSongListTopEnabled);
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.top, String.valueOf(TOP_ID), 10, 0L, locale);
		Assertions.assertNotNull(list);
		Assertions.assertTrue(list.getCount() > 0);
		Assertions.assertNotNull(list.getSongs());
		Assertions.assertTrue(list.getSongs().size() > 0);
	}

	@Test
	public void testGetSongListNews() {
		Assumptions.assumeTrue(testGetSongListEnabled && testGetSongListNewsEnabled);
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.news, String.valueOf(NEWS_ID), 10, 0L, locale);
		Assertions.assertNotNull(list);
		Assertions.assertTrue(list.getCount() > 0);
		Assertions.assertNotNull(list.getSongs());
		Assertions.assertTrue(list.getSongs().size() > 0);
	}

	@Test
	public void testGetSongFileList() {
		Assumptions.assumeTrue(testGetSongFileListEnabled);
		CatalogSongFileList list = catalogService.getSongFileList(SONG_ID, locale);
		Assertions.assertNotNull(list);
		Assertions.assertTrue(list.getLength() > 0);
		Assertions.assertNotNull(list.getSongFiles());
		Assertions.assertTrue(list.getSongFiles().size() > 0);
	}

	@Test
	public void testGetSelectionStyles() {
		Assumptions.assumeTrue(testGetSelectionEnabled && testGetSelectionStylesEnabled);
		CatalogSelection selection = catalogService.getSelection(CatalogSelectionType.styles, STYLE_ID, locale);
		Assertions.assertNotNull(selection);
		Assertions.assertEquals(STYLE_ID, selection.getId());
		Assertions.assertFalse(selection.getName().isEmpty());
	}

	@Test
	public void testGetSelectionTheme() {
		Assumptions.assumeTrue(testGetSelectionEnabled && testGetSelectionThemeEnabled);
		CatalogSelection selection = catalogService.getSelection(CatalogSelectionType.theme, THEME_ID, locale);
		Assertions.assertNotNull(selection);
		Assertions.assertEquals(THEME_ID, selection.getId());
		Assertions.assertFalse(selection.getName().isEmpty());
	}

	@Test
	public void testGetSelectionTop() {
		Assumptions.assumeTrue(testGetSelectionEnabled && testGetSelectionTopEnabled);
		CatalogSelection selection = catalogService.getSelection(CatalogSelectionType.top, TOP_ID, locale);
		Assertions.assertNotNull(selection);
		Assertions.assertEquals(TOP_ID, selection.getId());
		Assertions.assertFalse(selection.getName().isEmpty());
	}

	@Test
	public void testGetSelectionNews() {
		Assumptions.assumeTrue(testGetSelectionEnabled && testGetSelectionNewsEnabled);
		CatalogSelection selection = catalogService.getSelection(CatalogSelectionType.news, NEWS_ID, locale);
		Assertions.assertNotNull(selection);
		Assertions.assertEquals(NEWS_ID, selection.getId());
		Assertions.assertFalse(selection.getName().isEmpty());
	}

	@Test
	public void testGetSelectionListStyles() {
		Assumptions.assumeTrue(testGetSelectionListEnabled && testGetSelectionListStylesEnabled);
		CatalogSelectionList list = catalogService.getSelectionList(CatalogSelectionType.styles, locale);
		Assertions.assertNotNull(list);
		Assertions.assertEquals(list.getType(), CatalogSelectionType.styles);
		Assertions.assertNotNull(list.getSelections());
		Assertions.assertTrue(list.getSelections().size() > 0);
	}

	@Test
	public void testGetSelectionListTheme() {
		Assumptions.assumeTrue(testGetSelectionListEnabled && testGetSelectionListThemeEnabled);
		CatalogSelectionList list = catalogService.getSelectionList(CatalogSelectionType.theme, locale);
		Assertions.assertNotNull(list);
		Assertions.assertEquals(list.getType(), CatalogSelectionType.theme);
		Assertions.assertNotNull(list.getSelections());
		Assertions.assertTrue(list.getSelections().size() > 0);
	}

	@Test
	public void testGetSelectionListTop() {
		Assumptions.assumeTrue(testGetSelectionListEnabled && testGetSelectionListTopEnabled);
		CatalogSelectionList list = catalogService.getSelectionList(CatalogSelectionType.top, locale);
		Assertions.assertNotNull(list);
		Assertions.assertEquals(list.getType(), CatalogSelectionType.top);
		Assertions.assertNotNull(list.getSelections());
		Assertions.assertTrue(list.getSelections().size() > 0);
	}

	@Test
	public void testGetSelectionListNews() {
		Assumptions.assumeTrue(testGetSelectionListEnabled && testGetSelectionListNewsEnabled);
		CatalogSelectionList list = catalogService.getSelectionList(CatalogSelectionType.news, locale);
		Assertions.assertNotNull(list);
		Assertions.assertEquals(list.getType(), CatalogSelectionType.news);
		Assertions.assertNotNull(list.getSelections());
		Assertions.assertTrue(list.getSelections().size() > 0);
	}

}
