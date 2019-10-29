package me.crespel.karaplan.service.impl;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.ConfigurableConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.SongComment;
import me.crespel.karaplan.domain.SongVote;
import me.crespel.karaplan.domain.Style;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.model.CatalogStyle;
import me.crespel.karaplan.repository.SongRepo;
import me.crespel.karaplan.repository.SongVoteRepo;
import me.crespel.karaplan.service.ArtistService;
import me.crespel.karaplan.service.CatalogService;
import me.crespel.karaplan.service.SongService;
import me.crespel.karaplan.service.StyleService;

@Service
public class SongServiceImpl implements SongService {

	@Autowired
	protected SongRepo songRepo;

	@Autowired
	protected SongVoteRepo songVoteRepo;

	@Autowired
	protected CatalogService catalogService;

	@Autowired
	protected ArtistService artistService;

	@Autowired
	protected StyleService styleService;

	protected final ConfigurableConversionService conversionService;

	public SongServiceImpl() {
		conversionService = new DefaultConversionService();
		conversionService.addConverter(new CatalogSongToSongConverter());
		conversionService.addConverter(new CatalogStyleToStyleConverter());
	}

	@Override
	public Set<Song> findAll() {
		return Sets.newLinkedHashSet(songRepo.findAll());
	}

	@Override
	public Set<Song> findAll(Pageable pageable) {
		return Sets.newLinkedHashSet(songRepo.findAll(pageable));
	}

	@Override
	public Optional<Song> findById(Long id) {
		return songRepo.findById(id);
	}

	@Override
	public Optional<Song> findByCatalogId(Long catalogId) {
		return findByCatalogId(catalogId, null);
	}

	@Override
	public Optional<Song> findByCatalogId(Long catalogId, Locale locale) {
		Optional<Song> song = songRepo.findByCatalogId(catalogId);
		if (!song.isPresent()) {
			song = Optional.ofNullable(conversionService.convert(catalogService.getSong(catalogId, locale), Song.class));
		}
		return song;
	}

	@Override
	public Set<Song> search(CatalogSongListType type, String query, Pageable pageable) {
		return search(type, query, pageable, null);
	}

	@Override
	public Set<Song> search(CatalogSongListType type, String query, Pageable pageable, Locale locale) {
		Set<Song> resultSongs = Sets.newLinkedHashSet();

		CatalogSongList catalogSongList = catalogService.getSongList(type, query, pageable.getPageSize(), pageable.getOffset(), locale);
		if (catalogSongList.getSongs() != null) {
			// Convert catalog songs
			Set<Song> catalogSongs = catalogSongList.getSongs().stream()
					.map(it -> conversionService.convert(it, Song.class))
					.collect(Collectors.toCollection(LinkedHashSet::new));

			// Find all catalog IDs
			Set<Long> catalogSongIds = catalogSongs.stream()
					.map(Song::getCatalogId)
					.collect(Collectors.toCollection(LinkedHashSet::new));

			// Find all matching local songs
			Set<Song> localSongs = Sets.newLinkedHashSet(songRepo.findAllByCatalogIdIn(catalogSongIds));

			// Merge results
			resultSongs.addAll(Stream.of(catalogSongs, localSongs)
					.flatMap(Collection::stream)
					.collect(Collectors.toMap(Song::getCatalogId, Function.identity(), (catalog, local) -> local, LinkedHashMap::new))
					.values());
		}
		return resultSongs;
	}

	@Override
	@Transactional
	public Song save(Song song) {
		song.updateStats();
		return songRepo.save(song);
	}

	@Override
	@Transactional
	public Song vote(Song song, User user, int score) {
		if (song.getId() == null) {
			song = songRepo.save(song);
		}

		SongVote songVote = songVoteRepo.findBySongAndUser(song, user).orElseGet(() -> new SongVote()).setSong(song).setUser(user);
		if (songVote.getId() != null) {
			song.getVotes().remove(songVote);
		}
		if (score != 0) {
			songVote.setScore(score > 0 ? 1 : -1);
			song.getVotes().add(songVote);
		}
		return save(song);
	}

	@Override
	@Transactional
	public Song addComment(Song song, User user, String comment) {
		if (song.getId() == null) {
			song = songRepo.save(song);
		}

		song.getComments().add(new SongComment()
				.setSong(song)
				.setUser(user)
				.setComment(comment));
		return save(song);
	}

	@Override
	@Transactional
	public Song removeComment(Song song, long commentId) {
		return removeComment(song, null, commentId);
	}

	@Override
	@Transactional
	public Song removeComment(Song song, User user, long commentId) {
		song.getComments().removeIf(it -> it.getId() == commentId && (user == null || user.equals(it.getUser())));
		return save(song);
	}

	public class CatalogSongToSongConverter implements Converter<CatalogSong, Song> {

		@Override
		public Song convert(CatalogSong source) {
			Song song = new Song()
					.setCatalogId(source.getId())
					.setName(source.getName())
					.setDuration(source.getDuration())
					.setYear(source.getYear())
					.setImage(source.getImg())
					.setLyrics(source.getLyrics())
					.setRights(source.getRights())
					.setArtist(artistService.findByCatalogId(source.getArtist().getId()).orElse(null));
			if (source.getStyles() != null) {
				song.setStyles(source.getStyles().stream()
						.map(it -> styleService.findByCatalogId(it.getId()).orElse(conversionService.convert(it, Style.class)))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return song;
		}

	}

	public class CatalogStyleToStyleConverter implements Converter<CatalogStyle, Style> {

		@Override
		public Style convert(CatalogStyle source) {
			return new Style()
					.setCatalogId(source.getId())
					.setName(source.getName())
					.setImage(source.getImg());
		}

	}

}
