import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { AlertMessage } from '../models/alert-message';
import { AccountService } from '../services/account.service';
import { AlertService } from '../services/alert.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
  imports: [TranslatePipe]
})
export class LoginComponent implements OnInit, OnDestroy {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private accountService = inject(AccountService);
  private alertService = inject(AlertService);
  private translate = inject(TranslateService);

  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    if (this.route.snapshot.queryParamMap.has('error')) {
      this.translate.get(['login.errorTitle', 'login.errorText'])
        .pipe(takeUntil(this.destroy$))
        .subscribe(translations => {
          let message: AlertMessage = {
            severity: 'danger',
            title: translations['login.errorTitle'],
            text: translations['login.errorText']
          };
          this.alertService.addMessage(message);
        });
    }
    if (this.route.snapshot.queryParamMap.has('logout')) {
      this.translate.get(['login.logoutTitle', 'login.logoutText'])
        .pipe(takeUntil(this.destroy$))
        .subscribe(translations => {
          let message: AlertMessage = {
            severity: 'success',
            title: translations['login.logoutTitle'],
            text: translations['login.logoutText']
          };
          this.alertService.addMessage(message);
        });
    }
    this.accountService.getUser(false)
      .pipe(takeUntil(this.destroy$))
      .subscribe(user => {
        if (user) {
          this.router.navigate(['/songs']);
        }
      });
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
