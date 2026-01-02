import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { Router } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { Playlist } from '../models/playlist';
import { PlaylistsService } from '../services/playlists.service';
import { PlaylistEditModalComponent } from '../shared/playlist-edit-modal/playlist-edit-modal.component';
import { PlaylistLeaveModalComponent } from '../shared/playlist-leave-modal/playlist-leave-modal.component';
import { NgTemplateOutlet, NgClass } from '@angular/common';
import { DurationPipe } from '../shared/pipes/duration.pipe';

@Component({
  selector: 'app-playlists',
  templateUrl: './playlists.component.html',
  styleUrls: ['./playlists.component.css'],
  imports: [NgTemplateOutlet, NgClass, DurationPipe]
})
export class PlaylistsComponent implements OnInit, OnDestroy {
  private router = inject(Router);
  private modalService = inject(NgbModal);
  private playlistsService = inject(PlaylistsService);

  playlists: Playlist[] = [];
  playlistsRW: Playlist[] = [];
  playlistsRO: Playlist[] = [];
  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    this.refreshPlaylists();
  }

  refreshPlaylists() {
    this.playlistsService.getPlaylists(0, 100, ['name'])
      .pipe(takeUntil(this.destroy$))
      .subscribe(playlists => {
        this.playlists = playlists;
        this.playlistsRW = playlists.filter(p => !p.readOnly);
        this.playlistsRO = playlists.filter(p => p.readOnly);
      });
  }

  gotoPlaylist(playlist: Playlist) {
    this.router.navigate(['/playlists', playlist.id]);
  }

  createPlaylist() {
    let modal = this.modalService.open(PlaylistEditModalComponent);
    modal.componentInstance.playlist.set({});
    modal.result.then((result: Playlist) => {
      this.playlistsService.createPlaylist(result.name)
        .pipe(takeUntil(this.destroy$))
        .subscribe(playlist => this.gotoPlaylist(playlist));
    }, reason => {});
  }

  editPlaylist(playlist: Playlist) {
    let modal = this.modalService.open(PlaylistEditModalComponent);
    modal.componentInstance.playlist.set({id: playlist.id, name: playlist.name, readOnly: playlist.readOnly});
    modal.result.then((result: Playlist) => {
      this.playlistsService.savePlaylist(result)
        .pipe(takeUntil(this.destroy$))
        .subscribe(playlist => this.refreshPlaylists());
    }, reason => {});
  }

  leavePlaylist(playlist: Playlist) {
    let modal = this.modalService.open(PlaylistLeaveModalComponent);
    modal.componentInstance.playlist.set(playlist);
    modal.result.then((result: Playlist) => {
      this.playlistsService.leavePlaylist(result.id)
        .pipe(takeUntil(this.destroy$))
        .subscribe(response => this.refreshPlaylists());
    }, reason => {});
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
