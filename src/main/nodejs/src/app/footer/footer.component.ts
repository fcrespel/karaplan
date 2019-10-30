import { Component, OnInit } from '@angular/core';
import { ActuatorService } from '../services/actuator.service';
import { ActuatorInfo } from '../models/actuator-info';

@Component({
  selector: 'app-footer',
  templateUrl: './footer.component.html',
  styleUrls: ['./footer.component.css']
})
export class FooterComponent implements OnInit {

  actuatorInfo: ActuatorInfo;

  constructor(
    private actuatorService: ActuatorService
  ) { }

  ngOnInit() {
    this.actuatorService.getInfo().subscribe(actuatorInfo => this.actuatorInfo = actuatorInfo);
  }

}
