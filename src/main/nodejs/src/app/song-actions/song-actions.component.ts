import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { NgForm } from '@angular/forms';
import { AccountService } from '../services/account.service';
import { SongsService } from '../services/songs.service';
import { PlaylistsService } from '../services/playlists.service';
import { User } from '../models/user';
import { Song } from '../models/song';
import { SongVote } from '../models/song-vote';
import { SongComment } from '../models/song-comment';
import { Playlist } from '../models/playlist';
import { PlaylistSong } from '../models/playlist-song';

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
  @Input() showRemove: boolean = false;
  @Output() voteAdded = new EventEmitter<SongVote>();
  @Output() voteRemoved = new EventEmitter<SongVote>();
  @Output() commentAdded = new EventEmitter<SongComment>();
  @Output() commentRemoved = new EventEmitter<SongComment>();
  @Output() playlistAdded = new EventEmitter<PlaylistSong>();
  @Output() playlistRemoved = new EventEmitter<PlaylistSong>();
  @Output() songRemoved = new EventEmitter<Song>();

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

  trackByCommentId(index: number, comment: SongComment): number {
    return comment.id;
  }

  trackByPlaylistId(index: number, playlist: Playlist): number {
    return playlist.id;
  }

  voteUp() {
    let score = (this.vote && this.vote.score) == 1 ? 0 : 1;
    this.songsService.voteSongByCatalogId(this.song.catalogId, score).subscribe(song => {
      let previousVote = this.vote;
      this.updateSong(song);
      if (score != 0) {
        this.voteAdded.emit(this.vote);
      } else {
        this.voteRemoved.emit(previousVote);
      }
    });
  }

  voteDown() {
    let score = (this.vote && this.vote.score) == -1 ? 0 : -1;
    this.songsService.voteSongByCatalogId(this.song.catalogId, score).subscribe(song => {
      let previousVote = this.vote;
      this.updateSong(song);
      if (score != 0) {
        this.voteAdded.emit(this.vote);
      } else {
        this.voteRemoved.emit(previousVote);
      }
    });
  }

  addComment(comment: string, commentForm: NgForm) {
    this.songsService.addCommentToSongByCatalogId(this.song.catalogId, comment).subscribe(song => {
      commentForm.reset();
      this.updateSong(song);
      this.commentAdded.emit(song.comments.find(comment => comment.user.id == this.user.id));
    });
  }

  removeComment(comment: SongComment) {
    this.songsService.removeCommentFromSongByCatalogId(this.song.catalogId, comment.id).subscribe(song => {
      this.updateSong(song);
      this.commentRemoved.emit(comment);
    });
  }

  addToPlaylist(playlist: Playlist) {
    this.songsService.addSongToPlaylistByCatalogId(this.song.catalogId, playlist.id).subscribe(song => {
      this.updateSong(song);
      playlist.isSelected = true;
      this.playlistAdded.emit(new PlaylistSong(playlist, song));
    });
  }

  removeFromPlaylist(playlist: Playlist) {
    this.songsService.removeSongFromPlaylistByCatalogId(this.song.catalogId, playlist.id).subscribe(song => {
      this.updateSong(song);
      playlist.isSelected = false;
      this.playlistRemoved.emit(new PlaylistSong(playlist, song));
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
