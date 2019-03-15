import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute, ParamMap } from '@angular/router';
import { Observable } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { SongsService } from '../services/songs.service';
import { Song } from '../models/song';

@Component({
  selector: 'app-songs',
  templateUrl: './songs.component.html',
  styleUrls: ['./songs.component.css']
})
export class SongsComponent implements OnInit {

  query: string;
  songs$: Observable<Song[]>;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private songsService: SongsService
  ) { }

  ngOnInit() {
    this.songs$ = this.route.queryParamMap.pipe(
      switchMap((params: ParamMap) => 
        this.songsService.search(this.query = params.get('query'))
      )
    );
  }

  search(query: string) {
    this.router.navigate(['songs'], { queryParams: { query: query} });
  }

  voteUp(song: Song) {
    this.songsService.voteSongByCatalogId(song.catalogId, 1);
  }

  voteDown(song: Song) {
    this.songsService.voteSongByCatalogId(song.catalogId, -1);
  }
}
