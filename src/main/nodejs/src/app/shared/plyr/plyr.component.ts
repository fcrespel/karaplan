import { AfterViewInit, Component, ElementRef, EventEmitter, Input, OnChanges, OnDestroy, Output, SimpleChanges, ViewChild } from '@angular/core';
import Plyr from 'plyr';

@Component({
  selector: 'app-plyr, [plyr]',
  templateUrl: './plyr.component.html',
  styleUrls: ['./plyr.component.css']
})
export class PlyrComponent implements AfterViewInit, OnChanges, OnDestroy {

  @ViewChild('target') target!: ElementRef<HTMLMediaElement>;

  @Input() plyrOptions: Plyr.Options = {};
  @Input() plyrType: Plyr.MediaType = 'video';
  @Input() plyrTitle?: string;
  @Input() plyrPoster?: string;
  @Input() plyrSources: Plyr.Source[] = [];
  @Input() plyrTracks: Plyr.Track[] = [];
  @Output() plyrInit = new EventEmitter<Plyr>;
  @Output() plyrEvent = new EventEmitter<Plyr.PlyrEvent | Plyr.PlyrStateChangeEvent>;

  private plyr!: Plyr;
  private events: (Plyr.StandardEvent | Plyr.Html5Event | Plyr.YoutubeEvent)[] = ['waiting', 'canplay', 'playing', 'pause', 'ended'];

  ngAfterViewInit() {
    this.plyr = new Plyr(this.target.nativeElement, this.plyrOptions);
    this.events.forEach(name => this.plyr.on(name, event => this.plyrEvent.emit(event)));
    this.plyrInit.emit(this.plyr);
    this.updateSource();
  }

  ngOnChanges(changes: SimpleChanges) {
    if (['plyrType', 'plyrTitle', 'plyrPoster', 'plyrSources', 'plyrTracks'].filter(prop => prop in changes).length > 0) {
      this.updateSource();
    }
  }

  ngOnDestroy() {
    if (this.plyr) {
      this.plyr.destroy();
    }
  }

  private updateSource() {
    if (this.plyr) {
      this.plyr.source = {
        type: this.plyrType,
        title: this.plyrTitle,
        poster: this.plyrPoster,
        sources: this.plyrSources,
        tracks: this.plyrTracks,
      }
    }
  }

}
