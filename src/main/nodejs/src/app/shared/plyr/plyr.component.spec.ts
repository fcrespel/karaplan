import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PlyrComponent } from './plyr.component';

describe('PlyrComponent', () => {
  let component: PlyrComponent;
  let fixture: ComponentFixture<PlyrComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ PlyrComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(PlyrComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
