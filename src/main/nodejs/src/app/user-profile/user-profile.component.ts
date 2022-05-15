import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { AccountService } from '../services/account.service';
import { AlertService } from '../services/alert.service';
import { User } from '../models/user';
import { AlertMessage } from '../models/alert-message';

@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html',
  styleUrls: ['./user-profile.component.css']
})
export class UserProfileComponent implements OnInit {

  user?: User;
  tab: string = 'profile';
  deleteComments: boolean = false;
  confirmDeletion: string = '';

  constructor(
    private router: Router,
    private accountService: AccountService,
    private modalService: NgbModal,
    private alertService: AlertService
  ) { }

  ngOnInit() {
    this.accountService.getUser(false).subscribe(user => {
      this.user = user;
      if (!user) {
        this.router.navigate(['/login']);
      }
    });
  }

  switchTab($event: Event, tab: string) {
    $event.preventDefault();
    this.tab = tab;
  }

  updateUser(user: User) {
    this.accountService.updateUser(user).subscribe(user => {
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
      this.accountService.deleteUser(this.deleteComments).subscribe(() => {
        (document.getElementById('logoutForm') as HTMLFormElement).submit();
      });
    }, reason => {})
  }
}
