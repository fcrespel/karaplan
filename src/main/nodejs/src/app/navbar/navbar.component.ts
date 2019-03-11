import { Component, OnInit } from '@angular/core';
import { AccountService } from '../services/account.service';
import { User } from '../models/user';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit {

  navbarOpen: boolean = false;
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
