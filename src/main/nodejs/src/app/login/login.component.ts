import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AccountService } from '../services/account.service';
import { AlertService } from '../services/alert.service';
import { AlertMessage } from '../models/alert-message';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {

  isError: boolean;
  isLogout: boolean;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private accountService: AccountService,
    private alertService: AlertService
  ) { }

  ngOnInit() {
    if (this.route.snapshot.queryParamMap.has('error')) {
      let message = new AlertMessage();
      message.severity = 'danger';
      message.title = 'Error';
      message.text = 'Authentication failed';
      this.alertService.addMessage(message);
    }
    if (this.route.snapshot.queryParamMap.has('logout')) {
      let message = new AlertMessage();
      message.severity = 'success';
      message.title = 'Success';
      message.text = 'You have been signed out';
      this.alertService.addMessage(message);
    }
    if (this.route.snapshot.queryParamMap.has('delete')) {
      let message = new AlertMessage();
      message.severity = 'success';
      message.title = 'Success';
      message.text = 'Your account has been deleted';
      this.alertService.addMessage(message);
      
    } else {
      this.accountService.getUser(false).subscribe(user => {
        if (user) {
          this.router.navigate(['/songs']);
        }
      });
    }
  }

}
