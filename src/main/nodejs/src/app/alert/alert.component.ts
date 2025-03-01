import { Component, OnInit } from '@angular/core';
import { AlertService } from '../services/alert.service';
import { AlertMessage } from '../models/alert-message';

@Component({
  selector: 'app-alert',
  templateUrl: './alert.component.html',
  styleUrls: ['./alert.component.css'],
  standalone: false
})
export class AlertComponent implements OnInit {

  constructor(
    public alertService: AlertService
  ) { }

  ngOnInit() {
  }

  onClose(message: AlertMessage) {
    this.alertService.removeMessage(message);
  }

}
