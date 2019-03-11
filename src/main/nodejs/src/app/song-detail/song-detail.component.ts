import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute, ParamMap } from '@angular/router';
import { Observable } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { SongsService } from '../services/songs.service';
import { Song } from '../models/song';

@Component({
  selector: 'app-song-detail',
  templateUrl: './song-detail.component.html',
  styleUrls: ['./song-detail.component.css']
})
export class SongDetailComponent implements OnInit {

  song$: Observable<Song>;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private songsService: SongsService
  ) { }

  ngOnInit() {
    this.song$ = this.route.paramMap.pipe(
      switchMap((params: ParamMap) => 
        this.songsService.getSongByCatalogId(+params.get('catalogId'))
      )
    );
  }

}
