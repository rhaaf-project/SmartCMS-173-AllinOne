// ApiService - REST API communication with backend (VM 172)
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap } from 'rxjs/operators';

export interface User {
    userId: string;
    username: string;
    token: string;
}

export interface Channel {
    channelKey: string;
    name: string;
    extension: string;
    type: 'sip' | 'whatsapp' | 'teams';
    position: number;
}

export interface ChannelState {
    channelKey: string;
    isActive: boolean;
    isPtt: boolean;
    volume: number;
}

export interface AudioRecording {
    id: string;
    name: string;
    filePath: string;
    duration: number;
    createdAt: Date;
    isNew?: boolean;
}

@Injectable({
    providedIn: 'root'
})
export class ApiService {
    private baseUrl = 'http://localhost:3000/api'; // Local dev server
    private currentUser = new BehaviorSubject<User | null>(null);

    public currentUser$ = this.currentUser.asObservable();

    constructor(private http: HttpClient) { }

    private getHeaders(): HttpHeaders {
        const user = this.currentUser.getValue();
        return new HttpHeaders({
            'Content-Type': 'application/json',
            'Authorization': user ? `Bearer ${user.token}` : ''
        });
    }

    /**
     * Login user
     */
    login(username: string, password: string): Observable<User> {
        return this.http.post<User>(`${this.baseUrl}/login`, { username, password })
            .pipe(
                tap(user => {
                    this.currentUser.next(user);
                    localStorage.setItem('turret_user', JSON.stringify(user));
                })
            );
    }

    /**
     * Logout user
     */
    logout(): void {
        this.currentUser.next(null);
        localStorage.removeItem('turret_user');
    }

    /**
     * Restore session from localStorage
     */
    restoreSession(): void {
        const stored = localStorage.getItem('turret_user');
        if (stored) {
            try {
                const user = JSON.parse(stored) as User;
                this.currentUser.next(user);
            } catch {
                localStorage.removeItem('turret_user');
            }
        }
    }

    /**
     * Get user lines (SIP extensions assigned to user)
     */
    getLines(userId: string): Observable<any> {
        return this.http.get<any>(`${this.baseUrl}/user-data/${userId}`, {
            headers: this.getHeaders()
        });
    }

    /**
     * Get system configuration (WSS server, domain, etc)
     */
    getSystemConfig(): Observable<any> {
        return this.http.get<any>(`${this.baseUrl}/config`, {
            headers: this.getHeaders()
        });
    }

    /**
     * Get user channels/layout configuration
     */
    getUserChannels(userId: string): Observable<Channel[]> {
        return this.http.get<Channel[]>(`${this.baseUrl}/user/${userId}/channels`, {
            headers: this.getHeaders()
        });
    }

    /**
     * Save channel state
     */
    saveChannelState(userId: string, states: ChannelState[]): Observable<void> {
        return this.http.post<void>(`${this.baseUrl}/user/${userId}/channel-state`, { states }, {
            headers: this.getHeaders()
        });
    }

    /**
     * Load channel state
     */
    loadChannelState(userId: string): Observable<ChannelState[]> {
        return this.http.get<ChannelState[]>(`${this.baseUrl}/user/${userId}/channel-state`, {
            headers: this.getHeaders()
        });
    }

    /**
     * Get audio recordings list
     */
    getRecordings(userId: string): Observable<AudioRecording[]> {
        return this.http.get<AudioRecording[]>(`${this.baseUrl}/audio/${userId}`, {
            headers: this.getHeaders()
        });
    }

    /**
     * Upload audio recording
     */
    uploadRecording(userId: string, file: Blob, name: string): Observable<AudioRecording> {
        const formData = new FormData();
        formData.append('file', file, `${name}.wav`);
        formData.append('name', name);

        return this.http.post<AudioRecording>(`${this.baseUrl}/audio/${userId}`, formData, {
            headers: new HttpHeaders({
                'Authorization': this.currentUser.getValue()?.token ? `Bearer ${this.currentUser.getValue()?.token}` : ''
            })
        });
    }

    /**
     * Delete audio recording
     */
    deleteRecording(userId: string, recordingId: string): Observable<void> {
        return this.http.delete<void>(`${this.baseUrl}/audio/${userId}/${recordingId}`, {
            headers: this.getHeaders()
        });
    }

    /**
     * Rename audio recording
     */
    renameRecording(userId: string, recordingId: string, newName: string): Observable<AudioRecording> {
        return this.http.patch<AudioRecording>(`${this.baseUrl}/audio/${userId}/${recordingId}`, { name: newName }, {
            headers: this.getHeaders()
        });
    }
}
