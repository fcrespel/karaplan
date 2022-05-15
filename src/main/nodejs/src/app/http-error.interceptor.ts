import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { AlertService } from './services/alert.service';
import { AlertMessage } from './models/alert-message';

@Injectable()
export class HttpErrorInterceptor implements HttpInterceptor {

  constructor(
    private router: Router,
    private alertService: AlertService
  ) { }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(req).pipe(
      catchError((err: any) => {
        if (err instanceof HttpErrorResponse) {
          if (err.status == 401) {
            this.router.navigate(['/login']);
          } else {
            let message: AlertMessage = {
              severity: 'danger',
              title: err.error?.error || 'Error',
              text: err.error?.message || err.message,
              code: err.error?.status || err.status
            }
            this.alertService.addMessage(message);
          }
        }
        return throwError(err);
      })
    );
  }

}
