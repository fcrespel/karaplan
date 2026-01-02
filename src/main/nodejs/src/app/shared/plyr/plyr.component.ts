import { AfterViewInit, Component, ElementRef, OnChanges, OnDestroy, SimpleChanges, input, output, viewChild } from '@angular/core';
import * as Plyr from 'plyr';

@Component({
  selector: 'app-plyr, [plyr]',
  templateUrl: './plyr.component.html',
  styleUrls: ['./plyr.component.css']
})
export class PlyrComponent implements AfterViewInit, OnChanges, OnDestroy {

  readonly target = viewChild.required<ElementRef<HTMLMediaElement>>('target');

  readonly plyrOptions = input<Plyr.Options>({});
  readonly plyrType = input<Plyr.MediaType>('video');
  readonly plyrTitle = input<string>();
  readonly plyrPoster = input<string>();
  readonly plyrSources = input<Plyr.Source[]>([]);
  readonly plyrTracks = input<Plyr.Track[]>([]);
  readonly plyrInit = output<Plyr>();
  readonly plyrEvent = output<Plyr.PlyrEvent | Plyr.PlyrStateChangeEvent>();

  private plyr!: Plyr;
  private events: (Plyr.StandardEvent | Plyr.Html5Event | Plyr.YoutubeEvent)[] = ['waiting', 'canplay', 'playing', 'pause', 'ended'];

  ngAfterViewInit() {
    this.plyr = new Plyr.default(this.target().nativeElement, this.plyrOptions());
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
        type: this.plyrType(),
        title: this.plyrTitle(),
        poster: this.plyrPoster(),
        sources: this.plyrSources(),
        tracks: this.plyrTracks(),
      }
    }
  }

}
