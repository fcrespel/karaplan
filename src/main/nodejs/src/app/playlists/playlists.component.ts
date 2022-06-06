import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { PlaylistsService } from '../services/playlists.service';
import { PlaylistEditModalComponent } from '../shared/playlist-edit-modal/playlist-edit-modal.component';
import { PlaylistLeaveModalComponent } from '../shared/playlist-leave-modal/playlist-leave-modal.component';
import { Playlist } from '../models/playlist';

@Component({
  selector: 'app-playlists',
  templateUrl: './playlists.component.html',
  styleUrls: ['./playlists.component.css']
})
export class PlaylistsComponent implements OnInit {

  playlists: Playlist[] = [];
  playlistsRW: Playlist[] = [];
  playlistsRO: Playlist[] = [];

  constructor(
    private router: Router,
    private modalService: NgbModal,
    private playlistsService: PlaylistsService
  ) { }

  ngOnInit() {
    this.refreshPlaylists();
  }

  refreshPlaylists() {
    this.playlistsService.getPlaylists(0, 100, ['name']).subscribe(playlists => {
      this.playlists = playlists;
      this.playlistsRW = playlists.filter(p => !p.readOnly);
      this.playlistsRO = playlists.filter(p => p.readOnly);
    });
  }

  trackByPlaylistId(index: number, playlist: Playlist): number {
    return playlist.id;
  }

  gotoPlaylist(playlist: Playlist) {
    this.router.navigate(['/playlists', playlist.id]);
  }

  createPlaylist() {
    let modal = this.modalService.open(PlaylistEditModalComponent);
    modal.componentInstance.playlist = {};
    modal.result.then((result: Playlist) => {
      this.playlistsService.createPlaylist(result.name).subscribe(playlist => {
        this.gotoPlaylist(playlist);
      });
    }, reason => {});
  }

  editPlaylist(playlist: Playlist) {
    let modal = this.modalService.open(PlaylistEditModalComponent);
    modal.componentInstance.playlist = {id: playlist.id, name: playlist.name, readOnly: playlist.readOnly};
    modal.result.then((result: Playlist) => {
      this.playlistsService.savePlaylist(result).subscribe(playlist => {
        this.refreshPlaylists();
      });
    }, reason => {});
  }

  leavePlaylist(playlist: Playlist) {
    let modal = this.modalService.open(PlaylistLeaveModalComponent);
    modal.componentInstance.playlist = playlist;
    modal.result.then((result: Playlist) => {
      this.playlistsService.leavePlaylist(result.id).subscribe(response => {
        this.refreshPlaylists();
      });
    }, reason => {});
  }

}
