import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { shareReplay } from 'rxjs/operators';
import { ActuatorInfo } from '../models/actuator-info';

@Injectable({
  providedIn: 'root'
})
export class ActuatorService {
  private actuatorUrl = 'actuator';
  private info$: Observable<ActuatorInfo>;

  constructor(
    private http: HttpClient
  ) { }

  getInfo(): Observable<ActuatorInfo> {
    const url = `${this.actuatorUrl}/info`;
    if (this.info$ == null) {
      this.info$ = this.http.get<ActuatorInfo>(url).pipe(shareReplay(1));
    }
    return this.info$;
  }
}
