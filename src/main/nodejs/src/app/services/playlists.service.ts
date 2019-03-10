import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
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
    const url = `${this.playlistsUrl}?name=${name}`
    return this.http.post<Playlist>(url, null);
  }

  getPlaylist(id: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${id}`
    return this.http.get<Playlist>(url);
  }

  addSongByCatalogId(id: number, catalogId: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${id}/song/${catalogId}`
    return this.http.post<Playlist>(url, null);
  }

  removeSongByCatalogId(id: number, catalogId: number): Observable<Playlist> {
    const url = `${this.playlistsUrl}/${id}/song/${catalogId}`
    return this.http.delete<Playlist>(url);
  }
}
