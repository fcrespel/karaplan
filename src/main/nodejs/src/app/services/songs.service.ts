import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Song } from '../models/song';
import { SongComment } from '../models/song-comment';
import { SongVote } from '../models/song-vote';

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

  search(query: string): Observable<Song[]> {
    const url = `${this.songsUrl}/search?query=${query}`;
    return this.http.get<Song[]>(url);
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
    const url = `${this.songsUrl}/${catalogId}/vote?score=${score}`;
    return this.http.post<SongVote>(url, null);
  }
}
