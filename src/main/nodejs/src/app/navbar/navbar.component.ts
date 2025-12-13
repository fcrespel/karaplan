import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { CookieService } from 'ngx-cookie-service';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { ActuatorInfo } from '../models/actuator-info';
import { User } from '../models/user';
import { AccountService } from '../services/account.service';
import { ActuatorService } from '../services/actuator.service';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css'],
  standalone: false
})
export class NavbarComponent implements OnInit, OnDestroy {
  private cookieService = inject(CookieService);
  private actuatorService = inject(ActuatorService);
  private accountService = inject(AccountService);

  navbarOpen: boolean = false;
  xsrfToken: string = '';
  actuatorInfo?: ActuatorInfo;
  user?: User;
  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    this.xsrfToken = this.cookieService.get('XSRF-TOKEN');
    this.actuatorService.getInfo()
      .pipe(takeUntil(this.destroy$))
      .subscribe(actuatorInfo => this.actuatorInfo = actuatorInfo);
    this.accountService.getUser()
      .pipe(takeUntil(this.destroy$))
      .subscribe(user => this.user = user);
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
