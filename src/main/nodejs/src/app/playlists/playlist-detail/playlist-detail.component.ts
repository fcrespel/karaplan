import { Location } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { NgForm } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { Subject } from 'rxjs';
import { switchMap, takeUntil } from 'rxjs/operators';
import { AlertMessage } from '../../models/alert-message';
import { Playlist } from '../../models/playlist';
import { PlaylistComment } from '../../models/playlist-comment';
import { PlaylistSong } from '../../models/playlist-song';
import { Song } from '../../models/song';
import { User } from '../../models/user';
import { AccountService } from '../../services/account.service';
import { AlertService } from '../../services/alert.service';
import { PlaylistsService } from '../../services/playlists.service';
import { PlaylistEditModalComponent } from '../../shared/playlist-edit-modal/playlist-edit-modal.component';
import { PlaylistLeaveModalComponent } from '../../shared/playlist-leave-modal/playlist-leave-modal.component';

@Component({
  selector: 'app-playlist-detail',
  templateUrl: './playlist-detail.component.html',
  styleUrls: ['./playlist-detail.component.css'],
  standalone: false
})
export class PlaylistDetailComponent implements OnInit, OnDestroy {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private location = inject(Location);
  private modalService = inject(NgbModal);
  private accountService = inject(AccountService);
  private playlistsService = inject(PlaylistsService);
  private alertService = inject(AlertService);

  user?: User;
  playlist?: Playlist;
  playlistMembers: string = '';
  commentText: string = '';
  karafunRemoteId: string = '';
  karafunBarId: string = '';
  shareUrl: string = '';
  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    this.accountService.getUser()
      .pipe(takeUntil(this.destroy$))
      .subscribe(user => this.user = user);
    this.route.paramMap
      .pipe(takeUntil(this.destroy$))
      .pipe(switchMap(params => 
        this.playlistsService.getPlaylist(+params.get('id')!, this.route.snapshot.queryParamMap.get('accessKey'))
      ))
      .subscribe(playlist => this.updatePlaylist(playlist));
  }

  updatePlaylist(playlist?: Playlist) {
    if (playlist !== undefined) {
      this.playlist = playlist;
    }
    if (this.playlist !== undefined) {
      let urlTree = this.router.createUrlTree(['/playlists', this.playlist.id], {
        queryParams: {accessKey: this.playlist.accessKey}
      });
      this.shareUrl = window.location.origin + this.location.prepareExternalUrl(urlTree.toString());
      this.playlistMembers = this.playlist.members ? this.playlist.members.map(user => user.displayName).join(', ') : '';
    }
  }

  joinPlaylist(playlist: Playlist) {
    this.playlistsService.joinPlaylist(playlist.id, this.route.snapshot.queryParamMap.get('accessKey')!)
      .pipe(takeUntil(this.destroy$))
      .subscribe(playlist => this.updatePlaylist(playlist));
  }

  leavePlaylist(playlist: Playlist) {
    let modal = this.modalService.open(PlaylistLeaveModalComponent);
    modal.componentInstance.playlist.set(playlist);
    modal.result.then((result: Playlist) => {
      this.playlistsService.leavePlaylist(result.id)
        .pipe(takeUntil(this.destroy$))
        .subscribe(response => this.router.navigate(['/playlists']));
    }, reason => {});
  }

  editPlaylist(playlist: Playlist) {
    let modal = this.modalService.open(PlaylistEditModalComponent);
    modal.componentInstance.playlist.set({id: playlist.id, name: playlist.name, readOnly: playlist.readOnly});
    modal.result.then((result: Playlist) => {
      this.playlistsService.savePlaylist(result)
        .pipe(takeUntil(this.destroy$))
        .subscribe(playlist => this.updatePlaylist(playlist));
    }, reason => {});
  }

  addComment(playlist: Playlist, comment: string, commentForm: NgForm) {
    this.playlistsService.addCommentToPlaylist(playlist.id, comment)
      .pipe(takeUntil(this.destroy$))
      .subscribe(playlist => {
        commentForm.reset();
        this.updatePlaylist(playlist);
      });
  }

  removeComment(playlist: Playlist, comment: PlaylistComment) {
    this.playlistsService.removeCommentFromPlaylist(playlist.id, comment.id)
      .pipe(takeUntil(this.destroy$))
      .subscribe(playlist => this.updatePlaylist(playlist));
  }

  onPlaylistRemoved(playlist: Playlist, playlistSong: PlaylistSong) {
    if (playlistSong.playlist?.id === playlist.id) {
      this.playlistsService.getPlaylist(playlist.id)
        .pipe(takeUntil(this.destroy$))
        .subscribe(playlist => this.updatePlaylist(playlist));
    }
  }

  onSongMoved(playlist: Playlist, songList: PlaylistSong[]) {
    let songIds: number[] = songList.map(playlistSong => playlistSong.song.id!);
    this.playlistsService.sortPlaylistCustom(playlist.id, songIds)
      .pipe(takeUntil(this.destroy$))
      .subscribe(playlist => this.updatePlaylist(playlist));
  }

  onSongRemoved(playlist: Playlist, song: Song) {
    this.playlistsService.removeSongFromPlaylist(playlist.id, song.catalogId)
      .pipe(takeUntil(this.destroy$))
      .subscribe(playlist => this.updatePlaylist(playlist));
  }

  sortPlaylist(playlist: Playlist, sortType: string, sortDirection?: string) {
    this.playlistsService.sortPlaylist(playlist.id, sortType, sortDirection)
      .pipe(takeUntil(this.destroy$))
      .subscribe(playlist => this.updatePlaylist(playlist));
  }

  exportPlaylistToKarafunRemote(playlist: Playlist, modalContent: any) {
    this.modalService.open(modalContent).result.then(remoteId => {
      if (remoteId) {
        this.playlistsService.exportPlaylistToKarafunRemote(playlist.id, remoteId)
          .pipe(takeUntil(this.destroy$))
          .subscribe(response => {
            let message: AlertMessage = {
              severity: 'success',
              title: 'Success',
              text: `Export to KaraFun Remote #${remoteId} completed successfully`
            };
            this.alertService.addMessage(message);
          });
      }
    }, reason => {});
  }

  exportPlaylistToKarafunBar(playlist: Playlist, modalContent: any) {
    this.modalService.open(modalContent).result.then(bookingId => {
      if (bookingId) {
        this.playlistsService.exportPlaylistToKarafunBar(playlist.id, bookingId)
          .pipe(takeUntil(this.destroy$))
          .subscribe(response => {
            let message: AlertMessage = {
              severity: 'success',
              title: 'Success',
              text: `Export to KaraFun Bar session #${bookingId} completed successfully`
            };
            this.alertService.addMessage(message);
          });
      }
    }, reason => {});
  }

  copyToClipboard(field: HTMLInputElement) {
    field.focus();
    field.select();
    document.execCommand('copy');
  }

  isMember(user?: User, playlist?: Playlist) {
    return user && playlist && playlist.members && playlist.members.findIndex(member => member.id == user.id) >= 0;
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
