import { Component, inject } from '@angular/core';
import { AlertService } from '../services/alert.service';
import { AlertMessage } from '../models/alert-message';

@Component({
  selector: 'app-alert',
  templateUrl: './alert.component.html',
  styleUrls: ['./alert.component.css'],
  standalone: false
})
export class AlertComponent {
  alertService = inject(AlertService);

  onClose(message: AlertMessage) {
    this.alertService.removeMessage(message);
  }

}
