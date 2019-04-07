import { ActivatedRoute } from '@angular/router';
import { AccountService } from './../services/account.service';
import { Component, OnInit, Input, Output, EventEmitter, ChangeDetectionStrategy } from '@angular/core';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { PlaylistsService } from '../services/playlists.service';
import { AlertService } from '../services/alert.service';
import { Playlist } from '../models/playlist';
import { Song } from '../models/song';
import { PlaylistSong } from '../models/playlist-song';
import { AlertMessage } from '../models/alert-message';
import { NgForm } from '@angular/forms';

@Component({
  selector: 'app-playlist-detail',
  templateUrl: './playlist-detail.component.html',
  styleUrls: ['./playlist-detail.component.css']
})
export class PlaylistDetailComponent implements OnInit {

  @Input() playlist: Playlist;
  @Output() delete = new EventEmitter<Playlist>();
  karafunRemoteId: string;
  karafunBarId: string;
  accessId: string;
  shareUrl: string;

  constructor(
    private modalService: NgbModal,
    private playlistsService: PlaylistsService,
    private route: ActivatedRoute,
    private alertService: AlertService
  ) { }

  ngOnInit() {
    this.route.queryParamMap.subscribe(params => {
      this.accessId = params.get('accessId');
      if (!!this.accessId) {
        this.playlistsService.unlockPlaylist(this.playlist.id, this.accessId).subscribe((data: any) => {
          this.playlist.readOnly = false;
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
      });
    }
  }

  onSongRemoved(song: Song) {
    this.playlistsService.removeSongFromPlaylist(this.playlist.id, song.catalogId).subscribe(playlist => {
      this.playlist = playlist;
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
    });
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
    });
  }

  openShareModal(shareModalContent) {
    this.shareUrl = `${document.location.href}?accessId=${this.playlist.accessKey}`;
    this.modalService.open(shareModalContent, { size: 'lg' });
  }

  unlockPlaylist(accessIdInputForm: NgForm) {
    this.playlistsService.unlockPlaylist(this.playlist.id, this.accessId).subscribe((data: any) => {
      this.playlist.readOnly = false;
      accessIdInputForm.reset();
    });
  }

  copyToClipboard(text) {
    let selBox = document.createElement('textarea');
    selBox.style.position = 'fixed';
    selBox.style.left = '0';
    selBox.style.top = '0';
    selBox.style.opacity = '0';
    selBox.value = text;
    document.body.appendChild(selBox);
    selBox.focus();
    selBox.select();
    document.execCommand('copy');
    document.body.removeChild(selBox);
    }

}
