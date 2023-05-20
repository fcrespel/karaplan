import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { ActuatorInfo } from '../models/actuator-info';
import { ActuatorService } from '../services/actuator.service';

@Component({
  selector: 'app-about',
  templateUrl: './about.component.html',
  styleUrls: ['./about.component.css']
})
export class AboutComponent implements OnInit, OnDestroy {

  actuatorInfo?: ActuatorInfo;
  destroy$: Subject<boolean> = new Subject<boolean>();

  constructor(
    private actuatorService: ActuatorService
  ) { }

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
