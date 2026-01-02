import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { User } from '../models/user';
import { AccountService } from '../services/account.service';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css'],
  imports: [RouterLink]
})
export class HomeComponent implements OnInit, OnDestroy {
  private accountService = inject(AccountService);

  user?: User;
  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    this.accountService.getUser()
      .pipe(takeUntil(this.destroy$))
      .subscribe(user => this.user = user);
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
