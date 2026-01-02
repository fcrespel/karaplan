import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { AlertMessage } from './models/alert-message';
import { AlertService } from './services/alert.service';

export const httpErrorInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const alertService = inject(AlertService);
  return next(req).pipe(
    catchError((err: any) => {
      if (err instanceof HttpErrorResponse) {
        if (err.status == 401) {
          router.navigate(['/login']);
        } else {
          let message: AlertMessage = {
            severity: 'danger',
            title: err.error?.error || 'Error',
            text: err.error?.message || err.message,
            code: err.error?.status || err.status
          }
          alertService.addMessage(message);
        }
      }
      return throwError(() => err);
    })
  );
}
