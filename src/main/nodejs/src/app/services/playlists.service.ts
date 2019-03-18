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

  getPlaylists(): Observable<Playlist[]> {
    return this.http.get<Playlist[]>(this.playlistsUrl);
  }

  createPlaylist(name: string): Observable<Playlist> {
    let params = new HttpParams().set('name', name);
    return this.http.post<Playlist>(this.playlistsUrl, null, {params: params});
  }

  getPlaylist(id: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${id}`
    return this.http.get<Playlist>(url);
  }

  deletePlaylist(id: number): Observable<Response> {
    const url = `${this.playlistsUrl}/${id}`
    return this.http.delete<Response>(url);
  }

  addSongByCatalogId(playlistId: number, catalogId: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlistId}/song/${catalogId}`
    return this.http.post<Playlist>(url, null);
  }

  removeSongByCatalogId(playlistId: number, catalogId: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${playlistId}/song/${catalogId}`
    return this.http.delete<Playlist>(url);
  }
}
