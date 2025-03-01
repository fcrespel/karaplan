import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { User } from '../models/user';
import { AccountService } from '../services/account.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css'],
  standalone: false
})
export class HomeComponent implements OnInit, OnDestroy {

  user?: User;
  destroy$: Subject<boolean> = new Subject<boolean>();

  constructor(
    private accountService: AccountService
  ) { }

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
