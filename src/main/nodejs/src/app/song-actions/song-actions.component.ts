import { Component, OnInit, Input } from '@angular/core';
import { AccountService } from '../services/account.service';
import { SongsService } from '../services/songs.service';
import { User } from '../models/user';
import { Song } from '../models/song';
import { Playlist } from '../models/playlist';
import { PlaylistsService } from '../services/playlists.service';
import { SongVote } from '../models/song-vote';

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

  user: User = null;
  playlists: Playlist[] = null;
  vote: SongVote;
  voteUpUsers: string;
  voteDownUsers: string;
  commentText: string;

  constructor(
    private accountService: AccountService,
    private songsService: SongsService,
    private playlistsService: PlaylistsService
  ) { }

  ngOnInit() {
    this.accountService.getPrincipal().subscribe(principal => {
      this.user = principal.user;
      this.updateSong(this.song);
    });
  }

  updateSong(song: Song) {
    this.song = song;
    if (this.user && song.votes) {
      this.vote = song.votes.find(vote => vote.user.id == this.user.id);
      this.voteUpUsers = song.votes.filter(vote => vote.score > 0).map(vote => vote.user.displayName).join(', ');
      this.voteDownUsers = song.votes.filter(vote => vote.score < 0).map(vote => vote.user.displayName).join(', ');
    } else {
      this.vote = undefined;
      this.voteUpUsers = undefined;
      this.voteDownUsers = undefined;
    }
  }

  voteUp() {
    let score = (this.vote && this.vote.score) == 1 ? 0 : 1;
    this.songsService.voteSongByCatalogId(this.song.catalogId, score).subscribe(song => {
      this.updateSong(song);
    });
  }

  voteDown() {
    let score = (this.vote && this.vote.score) == -1 ? 0 : -1;
    this.songsService.voteSongByCatalogId(this.song.catalogId, score).subscribe(song => {
      this.updateSong(song);
    });
  }

  addComment(comment: string) {
    this.songsService.addCommentToSongByCatalogId(this.song.catalogId, comment).subscribe(song => {
      this.updateSong(song);
      this.commentText = '';
    });
  }

  removeComment(commentId: number) {
    this.songsService.removeCommentFromSongByCatalogId(this.song.catalogId, commentId).subscribe(song => {
      this.updateSong(song);
    });
  }

  addToPlaylist(playlist: Playlist) {
    this.songsService.addSongToPlaylistByCatalogId(this.song.catalogId, playlist.id).subscribe(song => {
      this.updateSong(song);
      playlist.isSelected = true;
    });
  }

  removeFromPlaylist(playlist: Playlist) {
    this.songsService.removeSongFromPlaylistByCatalogId(this.song.catalogId, playlist.id).subscribe(song => {
      this.updateSong(song);
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
