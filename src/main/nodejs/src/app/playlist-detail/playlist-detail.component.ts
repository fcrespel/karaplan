import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { NgForm } from '@angular/forms';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { switchMap } from 'rxjs/operators';
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

  playlist: Playlist = null;
  karafunRemoteId: string;
  karafunBarId: string;
  accessKey: string;
  shareUrl: string;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private modalService: NgbModal,
    private playlistsService: PlaylistsService,
    private alertService: AlertService
  ) { }

  ngOnInit() {
    this.route.paramMap.pipe(switchMap(params => {
      if (this.route.snapshot.queryParamMap.has('accessKey')) {
        return this.playlistsService.joinPlaylist(+params.get('id'), this.route.snapshot.queryParamMap.get('accessKey'));
      } else {
        return this.playlistsService.getPlaylist(+params.get('id'));
      }
    })).subscribe(playlist => {
      this.playlist = playlist;
    });
  }

  deletePlaylist() {
    this.playlistsService.deletePlaylist(this.playlist.id).subscribe(response => {
      this.router.navigate(['/playlists']);
    });
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

  sortPlaylist(sortType: string, sortDirection: string) {
    this.playlistsService.sortPlaylist(this.playlist.id, sortType, sortDirection).subscribe(playlist => {
      this.playlist = playlist;
    });
  }

  exportPlaylistToKarafunRemote(modalContent) {
    this.modalService.open(modalContent).result.then(remoteId => {
      if (remoteId) {
        this.playlistsService.exportPlaylistToKarafunRemote(this.playlist.id, remoteId).subscribe(response => {
          let message = new AlertMessage();
          message.severity = 'success';
          message.title = 'Success';
          message.text = `Export to Karafun Remote #${remoteId} completed successfully`;
          this.alertService.addMessage(message);
        });
      }
    }, reason => {});
  }

  exportPlaylistToKarafunBar(modalContent) {
    this.modalService.open(modalContent).result.then(bookingId => {
      if (bookingId) {
        this.playlistsService.exportPlaylistToKarafunBar(this.playlist.id, bookingId).subscribe(response => {
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

  openUnlockModal(unlockModalContent) {
    this.accessKey = "";
    this.modalService.open(unlockModalContent).result.then((accessKey: string) => {
      this.playlistsService.joinPlaylist(this.playlist.id, accessKey).subscribe(playlist => {
        this.playlist = playlist;
      });
    }, reason => {});
  }

  copyToClipboard(field: HTMLInputElement) {
    field.focus();
    field.select();
    document.execCommand('copy');
  }

}
