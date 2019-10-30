import { Component, OnInit } from '@angular/core';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { CookieService } from 'ngx-cookie-service';
import { ActuatorService } from '../services/actuator.service';
import { AccountService } from '../services/account.service';
import { ActuatorInfo } from '../models/actuator-info';
import { User } from '../models/user';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit {

  navbarOpen: boolean = false;
  xsrfToken: string;
  actuatorInfo: ActuatorInfo;
  user: User;

  constructor(
    private cookieService: CookieService,
    private actuatorService: ActuatorService,
    private accountService: AccountService
  ) { }

  ngOnInit() {
    this.xsrfToken = this.cookieService.get('XSRF-TOKEN');
    this.actuatorService.getInfo().subscribe(actuatorInfo => this.actuatorInfo = actuatorInfo);
    this.accountService.getUser().subscribe(user => this.user = user);
  }

}
