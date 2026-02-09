// ChannelCellComponent - Individual channel cell with active/inactive states
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule } from '@ionic/angular';

export interface ChannelData {
    key: string;
    name: string;
    extension: string;
    type: 'sip' | 'whatsapp' | 'teams';
    position: number;
    isActive: boolean;
    isPtt: boolean;
    volume: number;
}

@Component({
    selector: 'app-channel-cell',
    standalone: true,
    imports: [CommonModule, IonicModule],
    templateUrl: './channel-cell.component.html',
    styleUrls: ['./channel-cell.component.scss']
})
export class ChannelCellComponent {
    @Input() channel!: ChannelData;
    @Output() pttDown = new EventEmitter<void>();
    @Output() pttUp = new EventEmitter<void>();

    private pttActive = false;

    get channelNumber(): number {
        return this.channel?.position || 0;
    }

    get channelLabel(): string {
        if (!this.channel) return '';
        // Show first 2 chars of name or channel number
        return this.channel.name.length > 2
            ? this.channel.name.substring(0, 2).toUpperCase()
            : `${this.channelNumber}`;
    }

    get typeIcon(): string {
        switch (this.channel?.type) {
            case 'whatsapp': return 'logo-whatsapp';
            case 'teams': return 'people';
            default: return 'call';
        }
    }

    onPttStart(event: Event): void {
        event.preventDefault();
        event.stopPropagation();
        if (!this.pttActive) {
            this.pttActive = true;
            this.pttDown.emit();
        }
    }

    onPttEnd(event: Event): void {
        event.preventDefault();
        event.stopPropagation();
        if (this.pttActive) {
            this.pttActive = false;
            this.pttUp.emit();
        }
    }
}
