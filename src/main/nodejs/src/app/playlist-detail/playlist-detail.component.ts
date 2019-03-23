import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { PlaylistsService } from '../services/playlists.service';
import { Playlist } from '../models/playlist';

@Component({
  selector: 'app-playlist-detail',
  templateUrl: './playlist-detail.component.html',
  styleUrls: ['./playlist-detail.component.css']
})
export class PlaylistDetailComponent implements OnInit {

  @Input() playlist: Playlist;
  @Output() delete = new EventEmitter<Playlist>();
  karafunRemoteId: string;

  constructor(
    private modalService: NgbModal,
    private playlistsService: PlaylistsService
  ) { }

  ngOnInit() {
  }

  deletePlaylist(playlist: Playlist) {
    this.delete.emit(playlist);
  }

  exportPlaylistToKarafun(playlist: Playlist, modalContent) {
    this.modalService.open(modalContent).result.then(remoteId => {
      if (remoteId) {
        this.playlistsService.exportPlaylistToKarafun(playlist.id, remoteId).subscribe(response => {});
      }
    });
  }

}
