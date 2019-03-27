import { Injectable } from '@angular/core';
import { AlertMessage } from '../models/alert-message';

@Injectable({
  providedIn: 'root'
})
export class AlertService {

  messages: AlertMessage[] = [];

  constructor() { }

  addMessage(message: AlertMessage) {
    this.messages.push(message);
  }

  removeMessage(message: AlertMessage) {
    let index = this.messages.indexOf(message);
    if (index >= 0) {
      this.messages.splice(index, 1);
    }
  }

}
