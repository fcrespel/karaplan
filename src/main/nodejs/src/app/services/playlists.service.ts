import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Playlist } from '../models/playlist';

@Injectable({
  providedIn: 'root'
})
export class PlaylistsService {
  private playlistsUrl = 'api/v1/playlists';

  constructor(
    private http: HttpClient
  ) { }

  getPlaylists(page: number = 0, size: number = 10, sort: string[] = []): Observable<Playlist[]> {
    let params = new HttpParams().appendAll({
      page: '' + page,
      size: '' + size,
      sort: sort
    });
    return this.http.get<Playlist[]>(this.playlistsUrl, {params: params});
  }

  createPlaylist(name: string): Observable<Playlist> {
    let params = new HttpParams().set('name', name);
    return this.http.post<Playlist>(this.playlistsUrl, null, {params: params});
  }

  getPlaylist(playlistId: number, accessKey?: string | null): Observable<Playlist> {
    let params = new HttpParams();
    if (accessKey) {
      params = params.set('accessKey', accessKey);
    }
    const url = `${this.playlistsUrl}/${playlistId}`
    return this.http.get<Playlist>(url, {params: params});
  }

  savePlaylist(playlist: Playlist): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlist.id}`
    return this.http.put<Playlist>(url, playlist);
  }

  joinPlaylist(playlistId: number, accessKey: string): Observable<Playlist> {
    let params = new HttpParams().set('accessKey', accessKey);
    const url = `${this.playlistsUrl}/${playlistId}/join`;
    return this.http.post<Playlist>(url, null, {params: params});
  }

  leavePlaylist(playlistId: number): Observable<Response> {
    const url = `${this.playlistsUrl}/${playlistId}/leave`;
    return this.http.post<Response>(url, null);
  }

  addSongToPlaylist(playlistId: number, catalogId: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlistId}/song/${catalogId}`
    return this.http.post<Playlist>(url, null);
  }

  removeSongFromPlaylist(playlistId: number, catalogId: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlistId}/song/${catalogId}`
    return this.http.delete<Playlist>(url);
  }

  addCommentToPlaylist(playlistId: number, comment: string): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlistId}/comment`;
    return this.http.post<Playlist>(url, comment);
  }

  removeCommentFromPlaylist(playlistId: number, commentId: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlistId}/comment/${commentId}`;
    return this.http.delete<Playlist>(url);
  }

  sortPlaylist(playlistId: number, sortType: string, sortDirection: string = 'asc'): Observable<Playlist> {
    let params = new HttpParams()
      .set('sortType', sortType)
      .set('sortDirection', sortDirection);
    const url = `${this.playlistsUrl}/${playlistId}/sort`;
    return this.http.post<Playlist>(url, null, {params: params});
  }

  sortPlaylistCustom(playlistId: number, songIds: number[]): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlistId}/sort/custom`;
    return this.http.post<Playlist>(url, songIds);
  }

  exportPlaylistToKarafunRemote(playlistId: number, remoteId: string): Observable<Response> {
    const url = `${this.playlistsUrl}/${playlistId}/export/karafun/${remoteId}`
    return this.http.post<Response>(url, null);
  }

  exportPlaylistToKarafunBar(playlistId: number, bookingId: string): Observable<Response> {
    const url = `${this.playlistsUrl}/${playlistId}/export/karafunbar/${bookingId}`
    return this.http.post<Response>(url, null);
  }
}
