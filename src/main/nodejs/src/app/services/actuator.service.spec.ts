import { TestBed } from '@angular/core/testing';

import { ActuatorService } from './actuator.service';

describe('ActuatorService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: ActuatorService = TestBed.inject(ActuatorService);
    expect(service).toBeTruthy();
  });
});
