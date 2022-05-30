import { Component, OnInit } from '@angular/core';
import { ActuatorService } from '../services/actuator.service';
import { ActuatorInfo } from '../models/actuator-info';

@Component({
  selector: 'app-about',
  templateUrl: './about.component.html',
  styleUrls: ['./about.component.css']
})
export class AboutComponent implements OnInit {

  actuatorInfo?: ActuatorInfo;

  constructor(
    private actuatorService: ActuatorService
  ) { }

  ngOnInit() {
    this.actuatorService.getInfo().subscribe(actuatorInfo => this.actuatorInfo = actuatorInfo);
  }

}
