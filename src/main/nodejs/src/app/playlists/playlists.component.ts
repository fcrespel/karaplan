import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { of } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { AccountService } from './../services/account.service';
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
  restrictedPlaylist: boolean;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private playlistsService: PlaylistsService,
    private accountService: AccountService
  ) { }

  ngOnInit() {
    this.route.paramMap.pipe(switchMap(params => {
      if (params.has('id')) {
        return this.playlistsService.getPlaylist(+params.get('id'));
      } else {
        return of(null);
      }
    })).subscribe(playlist => {
      this.playlist = playlist;
      this.updatePlaylist(playlist);
    });
    this.playlistsService.getPlaylists(0, 100, 'name').subscribe(playlists => {
      playlists.forEach(playlist => this.updatePlaylist(playlist));
      this.playlists = playlists;
    });
  }

  updatePlaylist(playlist: Playlist) {
    if (playlist) {
      if (!playlist.restricted) {
        playlist.readOnly = false;
      } else if (playlist.members) {
        this.accountService.getUser().subscribe(user => {
          playlist.readOnly = playlist.members.findIndex(record => record.id === user.id) < 0;
        });
      } else {
        playlist.readOnly = true;
      }
    }
  }

  trackByPlaylistId(index: number, playlist: Playlist): number {
    return playlist.id;
  }

  createPlaylist(name: string, restricted: boolean) {
    this.playlistsService.createPlaylist(name, restricted).subscribe(playlist => {
      this.router.navigate(['/playlists', playlist.id]);
    });
  }

  deletePlaylist(playlist: Playlist) {
    this.playlistsService.deletePlaylist(playlist.id).subscribe(() => {
      this.router.navigate(['/playlists']);
    });
  }

}
