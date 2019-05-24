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

  getPlaylists(page: number = 0, size: number = 10, sort: string = ''): Observable<Playlist[]> {
    let params = new HttpParams()
      .set('page', ''+page)
      .set('size', ''+size)
      .set('sort', sort);
    return this.http.get<Playlist[]>(this.playlistsUrl, {params: params});
  }

  getAuthorizedPlaylists(page: number = 0, size: number = 10, sort: string = ''): Observable<Playlist[]> {
    let params = new HttpParams()
      .set('page', ''+page)
      .set('size', ''+size)
      .set('sort', sort);
    return this.http.get<Playlist[]>(`${this.playlistsUrl}/authorized`, {params: params});
  }

  createPlaylist(name: string, restricted: boolean): Observable<Playlist> {
    let params = new HttpParams().set('name', name).set('restricted', restricted ? 'true' : 'false');
    return this.http.post<Playlist>(this.playlistsUrl, null, {params: params});
  }

  getPlaylist(id: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${id}`
    return this.http.get<Playlist>(url);
  }

  savePlaylist(playlist: Playlist): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlist.id}`
    return this.http.put<Playlist>(url, playlist);
  }

  deletePlaylist(id: number): Observable<Response> {
    const url = `${this.playlistsUrl}/${id}`
    return this.http.delete<Response>(url);
  }

  addSongToPlaylist(playlistId: number, catalogId: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlistId}/song/${catalogId}`
    return this.http.post<Playlist>(url, null);
  }

  removeSongFromPlaylist(playlistId: number, catalogId: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlistId}/song/${catalogId}`
    return this.http.delete<Playlist>(url);
  }

  joinPlaylist(playlistId: number, accessKey: string): Observable<Playlist> {
    let params = new HttpParams().set('accessKey', accessKey);
    const url = `${this.playlistsUrl}/${playlistId}/join`;
    return this.http.post<Playlist>(url, null, {params: params});
  }

  sortPlaylist(playlistId: number, sortType: string, sortDirection: string = 'asc'): Observable<Playlist> {
    let params = new HttpParams()
      .set('sortType', sortType)
      .set('sortDirection', sortDirection);
    const url = `${this.playlistsUrl}/${playlistId}/sort`;
    return this.http.post<Playlist>(url, null, {params: params});
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
