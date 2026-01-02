import { Pipe, PipeTransform } from '@angular/core';

@Pipe({ name: 'duration' })
export class DurationPipe implements PipeTransform {

  transform(value: number): string {
    let seconds = value;
    let hours = Math.floor(seconds / 3600);
    seconds -= hours * 3600;
    let minutes = Math.floor(seconds / 60);
    seconds -= minutes * 60;
    let minutesPadded = minutes.toString().padStart(2, '0');
    let secondsPadded = seconds.toString().padStart(2, '0');
    if (hours > 0) {
      return `${hours}:${minutesPadded}:${secondsPadded}`;
    } else if (minutes > 0) {
      return `${minutes}:${secondsPadded}`;
    } else {
      return `${seconds}`;
    }
  }

}
