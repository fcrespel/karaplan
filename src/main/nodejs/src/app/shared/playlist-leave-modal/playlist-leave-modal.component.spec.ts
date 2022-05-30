import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PlaylistLeaveModalComponent } from './playlist-leave-modal.component';

describe('PlaylistLeaveModalComponent', () => {
  let component: PlaylistLeaveModalComponent;
  let fixture: ComponentFixture<PlaylistLeaveModalComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ PlaylistLeaveModalComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(PlaylistLeaveModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
