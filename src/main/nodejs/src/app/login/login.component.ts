import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { AlertMessage } from '../models/alert-message';
import { AccountService } from '../services/account.service';
import { AlertService } from '../services/alert.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
  standalone: false
})
export class LoginComponent implements OnInit, OnDestroy {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private accountService = inject(AccountService);
  private alertService = inject(AlertService);

  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    if (this.route.snapshot.queryParamMap.has('error')) {
      let message: AlertMessage = {
        severity: 'danger',
        title: 'Error',
        text: 'Authentication failed'
      };
      this.alertService.addMessage(message);
    }
    if (this.route.snapshot.queryParamMap.has('logout')) {
      let message: AlertMessage = {
        severity: 'success',
        title: 'Success',
        text: 'You have been signed out'
      };
      this.alertService.addMessage(message);
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
