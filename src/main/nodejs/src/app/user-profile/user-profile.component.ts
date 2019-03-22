import { Component, OnInit } from '@angular/core';
import { AccountService } from '../services/account.service';
import { User } from '../models/user';

@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html',
  styleUrls: ['./user-profile.component.css']
})
export class UserProfileComponent implements OnInit {

  user: User = null;

  constructor(
    private accountService: AccountService
  ) { }

  ngOnInit() {
    this.accountService.getPrincipal().subscribe(principal => {
      this.user = principal.user;
    });
  }

  updateUser(user: User) {
    this.accountService.updateUser(user).subscribe(user => {
      this.user = user;
    });
  }

}
