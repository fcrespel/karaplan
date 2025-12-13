import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { shareReplay } from 'rxjs/operators';
import { ActuatorInfo } from '../models/actuator-info';

@Injectable({
  providedIn: 'root'
})
export class ActuatorService {
  private http = inject(HttpClient);

  private actuatorUrl = 'actuator';
  private info$?: Observable<ActuatorInfo>;

  getInfo(): Observable<ActuatorInfo> {
    const url = `${this.actuatorUrl}/info`;
    if (this.info$ === undefined) {
      this.info$ = this.http.get<ActuatorInfo>(url).pipe(shareReplay(1));
    }
    return this.info$;
  }
}
