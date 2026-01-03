import { Component, inject } from '@angular/core';
import { NgbToast } from '@ng-bootstrap/ng-bootstrap';
import { AlertMessage } from '../models/alert-message';
import { AlertService } from '../services/alert.service';

@Component({
  selector: 'app-alert',
  templateUrl: './alert.component.html',
  styleUrls: ['./alert.component.css'],
  imports: [NgbToast]
})
export class AlertComponent {
  alertService = inject(AlertService);

  onClose(message: AlertMessage) {
    this.alertService.removeMessage(message);
  }

}
