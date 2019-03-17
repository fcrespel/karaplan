import { Component, OnInit, Input } from '@angular/core';
import { SongsService } from '../services/songs.service';
import { Song } from '../models/song';
import { Playlist } from '../models/playlist';
import { PlaylistsService } from '../services/playlists.service';

@Component({
  selector: 'app-song-actions',
  templateUrl: './song-actions.component.html',
  styleUrls: ['./song-actions.component.css']
})
export class SongActionsComponent implements OnInit {

  @Input() song: Song;
  @Input() showVotes: boolean = true;
  @Input() showComments: boolean = true;
  @Input() showPlaylists: boolean = true;
  playlists: Playlist[] = null;
  commentText: string;

  constructor(
    private songsService: SongsService,
    private playlistsService: PlaylistsService
  ) { }

  ngOnInit() {
  }

  voteUp() {
    this.songsService.voteSongByCatalogId(this.song.catalogId, 1).subscribe(song => {
      this.song = song;
    });
  }

  voteDown() {
    this.songsService.voteSongByCatalogId(this.song.catalogId, -1).subscribe(song => {
      this.song = song;
    });
  }

  addComment(comment: string) {
    this.songsService.commentSongByCatalogId(this.song.catalogId, comment).subscribe(song => {
      this.song = song;
      this.commentText = '';
    });
  }

  addToPlaylist(playlist: Playlist) {
    this.songsService.addSongToPlaylistByCatalogId(this.song.catalogId, playlist.id).subscribe(song => {
      this.song = song;
      playlist.isSelected = true;
    });
  }

  removeFromPlaylist(playlist: Playlist) {
    this.songsService.removeSongFromPlaylistByCatalogId(this.song.catalogId, playlist.id).subscribe(song => {
      this.song = song;
      playlist.isSelected = false;
    });
  }

  togglePlaylist(playlist: Playlist) {
    if (playlist.isSelected) {
      this.removeFromPlaylist(playlist);
    } else {
      this.addToPlaylist(playlist);
    }
  }

  onPlaylistOpen() {
    if (this.playlists == null) {
      this.playlistsService.getPlaylists().subscribe(playlists => {
        playlists.forEach(playlist => {
          playlist.isSelected = (this.song.playlists && this.song.playlists.findIndex(songPlaylist => songPlaylist.id == playlist.id) >= 0);
        });
        this.playlists = playlists;
      });
    }
  }

}
