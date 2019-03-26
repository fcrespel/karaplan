import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
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
    this.playlistsService.getPlaylists(0, 100, 'name').subscribe(playlists => {
      this.playlists = playlists;
    });
  }

  loadPlaylist(playlistId: number) {
    this.playlistsService.getPlaylist(playlistId).subscribe(playlist => {
      this.playlist = playlist;
    });
  }

  trackByPlaylistId(index: number, playlist: Playlist): number {
    return playlist.id;
  }

  createPlaylist(name: string) {
    this.playlistsService.createPlaylist(name).subscribe(playlist => {
      this.router.navigate(['/playlists', playlist.id]);
    })
  }

  deletePlaylist(playlist: Playlist) {
    this.playlistsService.deletePlaylist(playlist.id).subscribe(() => {
      this.router.navigate(['/playlists']);
    });
  }

}
