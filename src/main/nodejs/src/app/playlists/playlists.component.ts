import { AccountService } from './../services/account.service';
import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { PlaylistsService } from '../services/playlists.service';
import { Playlist } from '../models/playlist';
import { User } from '../models/user';

@Component({
  selector: 'app-playlists',
  templateUrl: './playlists.component.html',
  styleUrls: ['./playlists.component.css']
})
export class PlaylistsComponent implements OnInit {

  playlists: Playlist[] = [];
  playlist: Playlist;
  playlistName: string;
  restrictedPlaylist: boolean;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private playlistsService: PlaylistsService,
    private accountService: AccountService
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

  canEdit(): void {
    if (!this.playlist.restricted) {
      this.playlist.readOnly = false;
    } else if (!!this.playlist.authorizedUsers) {
      this.accountService.getUser()
      .subscribe((user: User) => {
        this.playlist.readOnly = this.playlist.authorizedUsers.findIndex(record => record.id === user.id) < 0;
      });
    } else {
      this.playlist.readOnly = true;
    }
  }

  loadPlaylist(playlistId: number) {
    this.playlistsService.getPlaylist(playlistId).subscribe(playlist => {
      this.playlist = playlist;
      this.canEdit();
    });
  }

  trackByPlaylistId(index: number, playlist: Playlist): number {
    return playlist.id;
  }

  createPlaylist(name: string, restrictedPlaylist: boolean) {
    this.playlistsService.createPlaylist(name, restrictedPlaylist).subscribe(playlist => {
      this.router.navigate(['/playlists', playlist.id]);
    });
  }

  deletePlaylist(playlist: Playlist) {
    this.playlistsService.deletePlaylist(playlist.id).subscribe(() => {
      this.router.navigate(['/playlists']);
    });
  }

}
