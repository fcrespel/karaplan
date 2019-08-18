import { Component, OnInit, Input } from '@angular/core';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { Playlist } from '../models/playlist';

@Component({
  selector: 'app-playlist-modal',
  templateUrl: './playlist-modal.component.html',
  styleUrls: ['./playlist-modal.component.css']
})
export class PlaylistModalComponent implements OnInit {

  @Input() playlist: Playlist;

  constructor(
    public activeModal: NgbActiveModal
  ) { }

  ngOnInit() {
  }

}
