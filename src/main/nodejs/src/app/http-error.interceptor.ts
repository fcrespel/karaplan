import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { AlertService } from './services/alert.service';
import { AlertMessage } from './models/alert-message';

@Injectable()
export class HttpErrorInterceptor implements HttpInterceptor {

  constructor(
    private alertService: AlertService
  ) { }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(req).pipe(
      catchError((error: HttpErrorResponse) => {
        let message = new AlertMessage();
        message.severity = 'danger';
        message.title = 'HTTP error';
        message.code = error.status;
        message.text = error.message;
        this.alertService.addMessage(message);
        return throwError(error);
      })
    );
  }

}
