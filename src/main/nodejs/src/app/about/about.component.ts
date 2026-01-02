import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { ActuatorInfo } from '../models/actuator-info';
import { ActuatorService } from '../services/actuator.service';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';

@Component({
  selector: 'app-about',
  templateUrl: './about.component.html',
  styleUrls: ['./about.component.css'],
  imports: [RouterLink, DatePipe]
})
export class AboutComponent implements OnInit, OnDestroy {
  private actuatorService = inject(ActuatorService);

  actuatorInfo?: ActuatorInfo;
  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    this.actuatorService.getInfo()
      .pipe(takeUntil(this.destroy$))
      .subscribe(actuatorInfo => this.actuatorInfo = actuatorInfo);
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
