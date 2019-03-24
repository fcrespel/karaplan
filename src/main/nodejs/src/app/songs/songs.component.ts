import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { SongsService } from '../services/songs.service';
import { Song } from '../models/song';
import { CatalogSelection } from '../models/catalog-selection';

@Component({
  selector: 'app-songs',
  templateUrl: './songs.component.html',
  styleUrls: ['./songs.component.css']
})
export class SongsComponent implements OnInit {

  type: string = 'query';
  query: string = '';
  page: number = 0;
  limit: number = 10;
  hasMoreSongs: boolean = false;
  songs: Song[] = [];
  selections: CatalogSelection[] = [];

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private songsService: SongsService
  ) { }

  ngOnInit() {
    this.route.queryParamMap.subscribe(params => {
      this.type = params.get('type') || 'query';
      this.query = params.get('query') || '';
      this.page = 0;
      this.hasMoreSongs = false;
      if (this.type == 'query' || this.query) {
        this.songsService.searchSongs(this.type, this.query).subscribe(songs => {
          this.songs = songs;
          this.hasMoreSongs = songs.length == this.limit;
        });
        this.selections = [];
      } else {
        this.songs = [];
        this.songsService.getSelections(this.type).subscribe(selections => {
          this.selections = selections;
        });
      }
    });
  }

  onSearch(query: string) {
    this.router.navigate(['/songs'], { queryParams: { query: query } });
  }

  loadMoreSongs() {
    if (this.hasMoreSongs && (this.type == 'query' || this.query)) {
      this.songsService.searchSongs(this.type, this.query, ++this.page).subscribe(songs => {
        songs.forEach(song => this.songs.push(song));
        this.hasMoreSongs = songs.length == this.limit;
      });
    }
  }

}
