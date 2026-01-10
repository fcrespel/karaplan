import { DatePipe } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '@ngx-translate/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { ActuatorInfo } from '../models/actuator-info';
import { ActuatorService } from '../services/actuator.service';

@Component({
  selector: 'app-footer',
  templateUrl: './footer.component.html',
  styleUrls: ['./footer.component.css'],
  imports: [RouterLink, DatePipe, TranslatePipe]
})
export class FooterComponent implements OnInit, OnDestroy {
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
