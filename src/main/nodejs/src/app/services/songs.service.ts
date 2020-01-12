import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Song } from '../models/song';
import { CatalogSelection } from '../models/catalog-selection';
import { CatalogSongFile } from '../models/catalog-song-file';

@Injectable({
  providedIn: 'root'
})
export class SongsService {
  private songsUrl = 'api/v1/songs';

  constructor(
    private http: HttpClient
  ) { }

  getSongs(page: number = 0, size: number = 10, sort: string = ''): Observable<Song[]> {
    let params = new HttpParams()
      .set('page', ''+page)
      .set('size', ''+size)
      .set('sort', sort);
    return this.http.get<Song[]>(this.songsUrl, {params: params});
  }

  searchSongs(type: string, query: string, page: number = 0, limit: number = 10): Observable<Song[]> {
    const url = `${this.songsUrl}/search`;
    let params = new HttpParams()
      .set('type', type)
      .set('query', query)
      .set('page', ''+page)
      .set('limit', ''+limit);
    return this.http.get<Song[]>(url, {params: params});
  }

  getSelections(selectionType: string): Observable<CatalogSelection[]> {
    const url = `${this.songsUrl}/selections/${selectionType}`;
    return this.http.get<CatalogSelection[]>(url);
  }

  getSelection(selectionType: string, selectionId: number): Observable<CatalogSelection> {
    const url = `${this.songsUrl}/selections/${selectionType}/${selectionId}`;
    return this.http.get<CatalogSelection>(url);
  }

  getSong(catalogId: number): Observable<Song> {
    const url = `${this.songsUrl}/${catalogId}`;
    return this.http.get<Song>(url);
  }

  importSong(catalogId: number): Observable<Song> {
    const url = `${this.songsUrl}/${catalogId}`;
    return this.http.post<Song>(url, null);
  }

  getSongFiles(catalogId: number): Observable<CatalogSongFile[]> {
    const url = `${this.songsUrl}/${catalogId}/files`;
    return this.http.get<CatalogSongFile[]>(url);
  }

  voteSong(catalogId: number, score: number): Observable<Song> {
    const url = `${this.songsUrl}/${catalogId}/vote`;
    let params = new HttpParams().set('score', ''+score);
    return this.http.post<Song>(url, null, {params: params});
  }

  addCommentToSong(catalogId: number, comment: string): Observable<Song> {
    const url = `${this.songsUrl}/${catalogId}/comment`;
    return this.http.post<Song>(url, comment);
  }

  removeCommentFromSong(catalogId: number, commentId: number): Observable<Song> {
    const url = `${this.songsUrl}/${catalogId}/comment/${commentId}`;
    return this.http.delete<Song>(url);
  }

  addSongToPlaylist(catalogId: number, playlistId: number): Observable<Song> {
    const url = `${this.songsUrl}/${catalogId}/playlist/${playlistId}`;
    return this.http.post<Song>(url, null);
  }

  removeSongFromPlaylist(catalogId: number, playlistId: number): Observable<Song> {
    const url = `${this.songsUrl}/${catalogId}/playlist/${playlistId}`;
    return this.http.delete<Song>(url);
  }
}
