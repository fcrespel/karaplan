import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Song } from '../models/song';
import { SongComment } from '../models/song-comment';
import { SongVote } from '../models/song-vote';
import { CatalogSelection } from '../models/catalog-selection';

@Injectable({
  providedIn: 'root'
})
export class SongsService {
  private songsUrl = 'api/v1/songs';

  constructor(
    private http: HttpClient
  ) { }

  getSongs(): Observable<Song[]> {
    return this.http.get<Song[]>(this.songsUrl);
  }

  search(type: string, query: string, page: number = 0, limit: number = 10): Observable<Song[]> {
    const url = `${this.songsUrl}/search`;
    let params = new HttpParams()
      .set('type', type)
      .set('query', query)
      .set('page', ''+page)
      .set('limit', ''+limit);
    return this.http.get<Song[]>(url, {params: params});
  }

  getSelections(type: string): Observable<CatalogSelection[]> {
    const url = `${this.songsUrl}/selections`;
    let params = new HttpParams().set('type', type);
    return this.http.get<CatalogSelection[]>(url, {params: params});
  }

  getSongByCatalogId(catalogId: number): Observable<Song> {
    const url = `${this.songsUrl}/${catalogId}`;
    return this.http.get<Song>(url);
  }

  importSongByCatalogId(catalogId: number): Observable<Song> {
    const url = `${this.songsUrl}/${catalogId}`;
    return this.http.post<Song>(url, null);
  }

  commentSongByCatalogId(catalogId: number, comment: string): Observable<SongComment> {
    const url = `${this.songsUrl}/${catalogId}/comment`;
    return this.http.post<SongComment>(url, comment);
  }

  voteSongByCatalogId(catalogId: number, score: number): Observable<SongVote> {
    const url = `${this.songsUrl}/${catalogId}/vote`;
    let params = new HttpParams().set('score', ''+score);
    return this.http.post<SongVote>(url, null, {params: params});
  }
}
