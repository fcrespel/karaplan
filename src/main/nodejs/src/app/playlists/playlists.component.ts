import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { PlaylistsService } from '../services/playlists.service';
import { Playlist } from '../models/playlist';

@Component({
  selector: 'app-playlists',
  templateUrl: './playlists.component.html',
  styleUrls: ['./playlists.component.css']
})
export class PlaylistsComponent implements OnInit {

  playlists: Playlist[] = [];
  playlist: Playlist;
  playlistName: string;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private modalService: NgbModal,
    private playlistsService: PlaylistsService
  ) { }

  ngOnInit() {
    this.route.paramMap.subscribe(params => {
      if (params.has('id')) {
        this.loadPlaylist(+params.get('id'));
      } else {
        this.playlist = null;
      }
    });
    this.playlistsService.getPlaylists().subscribe(playlists => {
      this.playlists = playlists;
    });
  }

  loadPlaylist(playlistId: number) {
    this.playlistsService.getPlaylist(playlistId).subscribe(playlist => {
      this.playlist = playlist;
      if (this.playlist.songs) {
        this.playlist.duration = this.playlist.songs.reduce((d, song) => d + song.duration, 0);
      } else {
        this.playlist.duration = 0;
      }
    });
  }

  createPlaylist(name: string) {
    this.playlistsService.createPlaylist(name).subscribe(playlist => {
      this.playlist = playlist;
      this.playlist.duration = 0;
      this.playlists.push(playlist);
    })
  }

  deletePlaylist(playlist: Playlist) {
    this.playlistsService.deletePlaylist(playlist.id).subscribe(() => {
      let index = this.playlists.findIndex(p => p.id == playlist.id);
      if (index > -1) {
        this.playlists.splice(index, 1);
      }
      this.router.navigate(['/playlists']);
    });
  }

  exportPlaylistToKarafun(playlist: Playlist, modalContent) {
    this.modalService.open(modalContent).result.then(remoteId => {
      if (remoteId) {
        this.playlistsService.exportPlaylistToKarafun(playlist.id, remoteId).subscribe(response => {});
      }
    });
  }
}
