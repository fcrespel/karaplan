import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { PlaylistsService } from '../services/playlists.service';
import { Playlist } from '../models/playlist';
import { Song } from '../models/song';

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

  constructor(
    private modalService: NgbModal,
    private playlistsService: PlaylistsService
  ) { }

  ngOnInit() {
  }

  deletePlaylist(playlist: Playlist) {
    this.delete.emit(playlist);
  }

  onSongRemoved(song: Song) {
    this.playlistsService.removeSongFromPlaylist(this.playlist.id, song.catalogId).subscribe(playlist => {
      this.playlist = playlist;
    });
  }

  exportPlaylistToKarafunRemote(playlist: Playlist, modalContent) {
    this.modalService.open(modalContent).result.then(remoteId => {
      if (remoteId) {
        this.playlistsService.exportPlaylistToKarafunRemote(playlist.id, remoteId).subscribe(response => {});
      }
    });
  }

  exportPlaylistToKarafunBar(playlist: Playlist, modalContent) {
    this.modalService.open(modalContent).result.then(bookingId => {
      if (bookingId) {
        this.playlistsService.exportPlaylistToKarafunBar(playlist.id, bookingId).subscribe(response => {});
      }
    });
  }

}
