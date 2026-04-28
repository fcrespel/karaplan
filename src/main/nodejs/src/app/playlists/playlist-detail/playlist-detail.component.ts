import { Location, NgClass } from '@angular/common';
import { Component, OnDestroy, OnInit, Pipe, PipeTransform, inject, signal } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { NgbDropdown, NgbDropdownButtonItem, NgbDropdownItem, NgbDropdownMenu, NgbDropdownToggle } from '@ng-bootstrap/ng-bootstrap/dropdown';
import { TranslatePipe } from '@ngx-translate/core';
import { Subject } from 'rxjs';
import { debounceTime, switchMap, takeUntil } from 'rxjs/operators';
import { AlertMessage } from '../../models/alert-message';
import { Playlist } from '../../models/playlist';
import { PlaylistComment } from '../../models/playlist-comment';
import { PlaylistSong } from '../../models/playlist-song';
import { Song } from '../../models/song';
import { User } from '../../models/user';
import { AccountService } from '../../services/account.service';
import { AlertService } from '../../services/alert.service';
import { PlaylistsService } from '../../services/playlists.service';
import { DurationPipe } from '../../shared/pipes/duration.pipe';
import { ZXingScannerModule } from '@zxing/ngx-scanner';
import { PlaylistEditModalComponent } from '../../shared/playlist-edit-modal/playlist-edit-modal.component';
import { PlaylistLeaveModalComponent } from '../../shared/playlist-leave-modal/playlist-leave-modal.component';
import { SongListComponent } from '../../shared/song-list/song-list.component';

@Pipe({
  name: 'sumDurationByUser'
})
export class SumDurationByUserPipe implements PipeTransform {

  transform(playlist: Playlist, userId: number): number {
    if (!playlist?.songs || !userId) {
      return 0;
    }

    return playlist.songs.reduce((total: number, song: any) => {
      if (song?.createdBy?.id === userId) {
        return total + (song?.song?.duration ?? 0);
      }
      return total;
    }, 0);
  }
}


@Component({
  selector: 'app-playlist-detail',
  templateUrl: './playlist-detail.component.html',
  styleUrls: ['./playlist-detail.component.css'],
  imports: [RouterLink, NgClass, NgbDropdown, NgbDropdownToggle, NgbDropdownMenu, FormsModule, NgbDropdownButtonItem, NgbDropdownItem, SongListComponent, DurationPipe, TranslatePipe, SumDurationByUserPipe, ZXingScannerModule]
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
  filteredSongs: PlaylistSong[] = [];
  filterText: string = '';
  filterText$ = new Subject<string>();
  commentText: string = '';
  karafunRemoteId: string = '';
  karafunBarId: string = '';
  shareUrl: string = '';
  scanQrCodeEnabled = signal(false);
  scanQrCodeError = signal(false);
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
    this.filterText$
      .pipe(debounceTime(300), takeUntil(this.destroy$))
      .subscribe(text => this.applyFilter(text));
  }

  updatePlaylist(playlist?: Playlist) {
    if (playlist !== undefined) {
      if (playlist.members) {
        playlist.members.sort((a, b) => a.displayName.localeCompare(b.displayName));
      }
      this.playlist = playlist;
    }
    this.applyFilter(this.filterText);
    if (this.playlist !== undefined) {
      let urlTree = this.router.createUrlTree(['/playlists', this.playlist.id], {
        queryParams: {accessKey: this.playlist.accessKey}
      });
      this.shareUrl = window.location.origin + this.location.prepareExternalUrl(urlTree.toString());
    }
  }

  onFilterChange(text: string) {
    this.filterText$.next(text);
  }

  clearFilter() {
    this.filterText = '';
    this.applyFilter('');
  }

  private applyFilter(text: string) {
    const query = text.trim().toLowerCase();
    const songs = this.playlist?.songs ?? [];
    if (!query) {
      this.filteredSongs = songs;
    } else {
      this.filteredSongs = songs.filter(ps =>
        ps.song.name?.toLowerCase().includes(query) ||
        ps.song.artist?.name?.toLowerCase().includes(query) ||
        ps.createdBy?.displayName?.toLowerCase().includes(query)
      );
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

  parseKarafunRemoteQrCode(result: string) {
    const match = /(\d+)\/?$/.exec(result);
    if (match) {
      this.karafunRemoteId = match[1];
      this.scanQrCodeEnabled.set(false);
      this.scanQrCodeError.set(false);
    } else {
      this.scanQrCodeError.set(true);
    }
  }

  toggleQrCodeScanner() {
    this.scanQrCodeEnabled.set(!this.scanQrCodeEnabled());
    this.scanQrCodeError.set(false);
  }

  exportPlaylistToKarafunRemote(playlist: Playlist, modalContent: any) {
    this.modalService.open(modalContent).result.then(remoteId => {
      this.scanQrCodeEnabled.set(false);
      this.scanQrCodeError.set(false);
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
    }, reason => {
      this.scanQrCodeEnabled.set(false);
      this.scanQrCodeError.set(false);
    });
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
