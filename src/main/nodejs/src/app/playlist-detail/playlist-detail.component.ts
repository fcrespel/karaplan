import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { NgForm } from '@angular/forms';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { PlaylistsService } from '../services/playlists.service';
import { AlertService } from '../services/alert.service';
import { Playlist } from '../models/playlist';
import { Song } from '../models/song';
import { PlaylistSong } from '../models/playlist-song';
import { AlertMessage } from '../models/alert-message';

@Component({
  selector: 'app-playlist-detail',
  templateUrl: './playlist-detail.component.html',
  styleUrls: ['./playlist-detail.component.css']
})
export class PlaylistDetailComponent implements OnInit {

  @Input() playlist: Playlist;
  @Output() playlistChange = new EventEmitter<Playlist>();
  @Output() delete = new EventEmitter<Playlist>();
  karafunRemoteId: string;
  karafunBarId: string;
  accessKey: string;
  shareUrl: string;

  constructor(
    private route: ActivatedRoute,
    private modalService: NgbModal,
    private playlistsService: PlaylistsService,
    private alertService: AlertService
  ) { }

  ngOnInit() {
    this.route.queryParamMap.subscribe(params => {
      this.accessKey = params.get('accessKey');
      if (this.accessKey) {
        this.playlistsService.joinPlaylist(this.playlist.id, this.accessKey).subscribe(playlist => {
          this.playlist = playlist;
          this.playlistChange.emit(this.playlist);
        });
      }
    });
  }

  deletePlaylist(playlist: Playlist) {
    this.delete.emit(playlist);
  }

  onPlaylistRemoved(playlistSong: PlaylistSong) {
    if (playlistSong.playlist.id === this.playlist.id) {
      this.playlistsService.getPlaylist(this.playlist.id).subscribe(playlist => {
        this.playlist = playlist;
        this.playlistChange.emit(this.playlist);
      });
    }
  }

  onSongRemoved(song: Song) {
    this.playlistsService.removeSongFromPlaylist(this.playlist.id, song.catalogId).subscribe(playlist => {
      this.playlist = playlist;
      this.playlistChange.emit(this.playlist);
    });
  }

  exportPlaylistToKarafunRemote(playlist: Playlist, modalContent) {
    this.modalService.open(modalContent).result.then(remoteId => {
      if (remoteId) {
        this.playlistsService.exportPlaylistToKarafunRemote(playlist.id, remoteId).subscribe(response => {
          let message = new AlertMessage();
          message.severity = 'success';
          message.title = 'Success';
          message.text = `Export to Karafun Remote #${remoteId} completed successfully`;
          this.alertService.addMessage(message);
        });
      }
    }, reason => {});
  }

  exportPlaylistToKarafunBar(playlist: Playlist, modalContent) {
    this.modalService.open(modalContent).result.then(bookingId => {
      if (bookingId) {
        this.playlistsService.exportPlaylistToKarafunBar(playlist.id, bookingId).subscribe(response => {
          let message = new AlertMessage();
          message.severity = 'success';
          message.title = 'Success';
          message.text = `Export to Karafun Bar session #${bookingId} completed successfully`;
          this.alertService.addMessage(message);
        });
      }
    }, reason => {});
  }

  openShareModal(shareModalContent) {
    this.shareUrl = `${document.location.href}?accessKey=${this.playlist.accessKey}`;
    this.modalService.open(shareModalContent, { size: 'lg' });
  }

  unlockPlaylist(accessKeyInputForm: NgForm) {
    this.playlistsService.joinPlaylist(this.playlist.id, this.accessKey).subscribe(playlist => {
      this.playlist = playlist;
      this.playlistChange.emit(this.playlist);
      accessKeyInputForm.reset();
    });
  }

  copyToClipboard(field: HTMLInputElement) {
    field.focus();
    field.select();
    document.execCommand('copy');
  }

}
