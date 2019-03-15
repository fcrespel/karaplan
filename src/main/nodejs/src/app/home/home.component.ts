import { Component, OnInit } from '@angular/core';
import { AccountService } from '../services/account.service';
import { User } from '../models/user';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {

  user: User = null;

  constructor(
    private accountService: AccountService
  ) { }

  ngOnInit() {
    this.accountService.getPrincipal().subscribe(principal => {
      this.user = principal.user;
    });
  }

}
