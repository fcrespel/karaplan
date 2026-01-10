import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { TranslatePipe } from '@ngx-translate/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { AlertMessage } from '../../models/alert-message';
import { User } from '../../models/user';
import { AccountService } from '../../services/account.service';
import { AlertService } from '../../services/alert.service';

@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html',
  styleUrls: ['./user-profile.component.css'],
  imports: [RouterLink, FormsModule, TranslatePipe]
})
export class UserProfileComponent implements OnInit, OnDestroy {
  private router = inject(Router);
  private accountService = inject(AccountService);
  private modalService = inject(NgbModal);
  private alertService = inject(AlertService);

  user?: User;
  deleteComments: boolean = false;
  confirmDeletion: string = '';
  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    this.accountService.getUser(false)
      .pipe(takeUntil(this.destroy$))
      .subscribe(user => {
        this.user = user;
        if (!user) {
          this.router.navigate(['/login']);
        }
      });
  }

  updateUser(user: User) {
    this.accountService.updateUser(user)
      .pipe(takeUntil(this.destroy$))
      .subscribe(user => {
        this.user = user;
        let message: AlertMessage = {
          severity: 'success',
          title: 'Success',
          text: 'Your user profile has been updated'
        }
        this.alertService.addMessage(message);
        this.accountService.refreshCache();
      });
  }

  deleteAccount(modalContent: any) {
    this.modalService.open(modalContent).result.then(() => {
      this.accountService.deleteUser(this.deleteComments)
        .pipe(takeUntil(this.destroy$))
        .subscribe(() => (document.getElementById('logoutForm') as HTMLFormElement).submit());
    }, reason => {})
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
