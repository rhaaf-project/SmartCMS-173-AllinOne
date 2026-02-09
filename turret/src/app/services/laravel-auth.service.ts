import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, of, throwError } from 'rxjs';
import { map, catchError, switchMap } from 'rxjs/operators';

export interface LoginResponse {
    token: string;
    user: {
        id: number;
        name: string;
        email: string;
        use_ext: string;  // SIP extension assigned to user
    };
}

export interface Extension {
    id: number;
    extension: string;
    name: string;
    secret: string;
    context?: string;
    is_active?: boolean;
    sip_server?: string;
    created_at?: string;
    updated_at?: string;
}

export interface AuthResult {
    success: boolean;
    token?: string;
    extension?: Extension;
    user?: LoginResponse['user'];
    error?: string;
}

// Turret data interfaces
export interface Line {
    id: number;
    name: string;
    extension_number?: string;
    use_ext?: string;
    call_server_id?: number;
    is_active?: boolean;
}

export interface VPW {
    id: number;
    name: string;
    extension_number?: string;
    use_ext?: string;
    call_server_id?: number;
    is_active?: boolean;
}

export interface CAS {
    id: number;
    name: string;
    extension_number?: string;
    use_ext?: string;
    call_server_id?: number;
    is_active?: boolean;
}

export interface Intercom {
    id: number;
    name: string;
    extension_number?: string;
    ext?: string;
    call_server_id?: number;
    is_active?: boolean;
}

export interface PhonebookEntry {
    id: number;
    turret_user_id: number;
    name: string;
    phone: string;
    company?: string;
    email?: string;
    notes?: string;
    is_favourite?: boolean;
    is_archived?: boolean;
}

@Injectable({ providedIn: 'root' })
export class LaravelAuthService {
    private readonly API_URL = 'http://103.154.80.171/api';
    private token: string | null = null;

    constructor(private http: HttpClient) {
        // Load token from storage if exists
        this.token = localStorage.getItem('smartucx_auth_token');
    }

    /**
     * Login and get user's assigned extension
     * @param username - username or email
     * @param password - user password
     * @returns AuthResult with token and user's extension (use_ext)
     */
    login(username: string, password: string): Observable<AuthResult> {
        const headers = new HttpHeaders({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        });

        return this.http.post<LoginResponse>(`${this.API_URL}/login`, {
            email: username.includes('@') ? username : `${username}@smartx.local`,
            password: password
        }, { headers }).pipe(
            map(response => {
                // Store token
                this.token = response.token;
                localStorage.setItem('smartucx_auth_token', response.token);
                console.log('[Auth] Login successful, user:', response.user.name, 'ext:', response.user.use_ext);

                // Create extension object from user's use_ext
                const userExtension: Extension = {
                    id: response.user.id,
                    extension: response.user.use_ext,
                    name: response.user.name,
                    secret: 'Maja1234',  // Default password, can be fetched from extensions table if needed
                    sip_server: '103.154.80.172'
                };

                return {
                    success: true,
                    token: this.token || undefined,
                    extension: userExtension,
                    user: response.user
                } as AuthResult;
            }),
            catchError(err => {
                console.error('[Auth] Login failed:', err);
                return of({
                    success: false,
                    error: err.error?.message || err.message || 'Login failed'
                } as AuthResult);
            })
        );
    }

    /**
     * Get all extensions from Laravel API
     */
    getExtensions(): Observable<Extension[]> {
        const headers = new HttpHeaders({
            'Accept': 'application/json',
            'Authorization': `Bearer ${this.token}`
        });

        return this.http.get<Extension[]>(`${this.API_URL}/v1/extensions`, { headers }).pipe(
            catchError(err => {
                console.error('[Auth] Failed to fetch extensions:', err);
                return of([]);
            })
        );
    }

    /**
     * Get specific extension by ID
     */
    getExtension(id: number): Observable<Extension | null> {
        const headers = new HttpHeaders({
            'Accept': 'application/json',
            'Authorization': `Bearer ${this.token}`
        });

        return this.http.get<Extension>(`${this.API_URL}/v1/extensions/${id}`, { headers }).pipe(
            catchError(err => {
                console.error('[Auth] Failed to fetch extension:', err);
                return of(null);
            })
        );
    }

    // ==================== TURRET DATA METHODS ====================

    /**
     * Get all lines from CMS
     */
    getLines(): Observable<Line[]> {
        return this.http.get<{ data: Line[] }>(`${this.API_URL}/lines`, { headers: this.getAuthHeaders() }).pipe(
            map(response => response.data || []),
            catchError(err => {
                console.error('[CMS] Failed to fetch lines:', err);
                return of([]);
            })
        );
    }

    /**
     * Get all VPWs (Virtual Private Wires) from CMS
     */
    getVPWs(): Observable<VPW[]> {
        return this.http.get<{ data: VPW[] }>(`${this.API_URL}/vpws`, { headers: this.getAuthHeaders() }).pipe(
            map(response => response.data || []),
            catchError(err => {
                console.error('[CMS] Failed to fetch VPWs:', err);
                return of([]);
            })
        );
    }

    /**
     * Get all CAS devices from CMS
     */
    getCAS(): Observable<CAS[]> {
        return this.http.get<{ data: CAS[] }>(`${this.API_URL}/cas`, { headers: this.getAuthHeaders() }).pipe(
            map(response => response.data || []),
            catchError(err => {
                console.error('[CMS] Failed to fetch CAS:', err);
                return of([]);
            })
        );
    }

    /**
     * Get all intercoms from CMS
     */
    getIntercoms(): Observable<Intercom[]> {
        return this.http.get<{ data: Intercom[] }>(`${this.API_URL}/intercoms`, { headers: this.getAuthHeaders() }).pipe(
            map(response => response.data || []),
            catchError(err => {
                console.error('[CMS] Failed to fetch intercoms:', err);
                return of([]);
            })
        );
    }

    /**
     * Get phonebook entries for a turret user
     */
    getPhonebook(turretUserId: number): Observable<PhonebookEntry[]> {
        return this.http.get<{ data: PhonebookEntry[] }>(`${this.API_URL}/turret-user-phonebooks?turret_user_id=${turretUserId}`, { headers: this.getAuthHeaders() }).pipe(
            map(response => response.data || []),
            catchError(err => {
                console.error('[CMS] Failed to fetch phonebook:', err);
                return of([]);
            })
        );
    }

    /**
     * Add phonebook entry
     */
    addPhonebookEntry(entry: Partial<PhonebookEntry>): Observable<PhonebookEntry | null> {
        return this.http.post<{ data: PhonebookEntry }>(`${this.API_URL}/turret-user-phonebooks`, entry, { headers: this.getAuthHeaders() }).pipe(
            map(response => response.data),
            catchError(err => {
                console.error('[CMS] Failed to add phonebook entry:', err);
                return of(null);
            })
        );
    }

    /**
     * Update phonebook entry
     */
    updatePhonebookEntry(id: number, entry: Partial<PhonebookEntry>): Observable<PhonebookEntry | null> {
        return this.http.put<{ data: PhonebookEntry }>(`${this.API_URL}/turret-user-phonebooks/${id}`, entry, { headers: this.getAuthHeaders() }).pipe(
            map(response => response.data),
            catchError(err => {
                console.error('[CMS] Failed to update phonebook entry:', err);
                return of(null);
            })
        );
    }

    /**
     * Delete phonebook entry
     */
    deletePhonebookEntry(id: number): Observable<boolean> {
        return this.http.delete<any>(`${this.API_URL}/turret-user-phonebooks/${id}`, { headers: this.getAuthHeaders() }).pipe(
            map(() => true),
            catchError(err => {
                console.error('[CMS] Failed to delete phonebook entry:', err);
                return of(false);
            })
        );
    }

    /**
     * Helper to get auth headers
     */
    private getAuthHeaders(): HttpHeaders {
        return new HttpHeaders({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`
        });
    }

    // ==================== AUTH METHODS ====================

    /**
     * Logout and clear token
     */
    logout(): void {
        this.token = null;
        localStorage.removeItem('smartucx_auth_token');
        console.log('[Auth] Logged out');
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated(): boolean {
        return !!this.token;
    }

    /**
     * Get current token
     */
    getToken(): string | null {
        return this.token;
    }

    // ==================== CHANNEL STATE METHODS ====================

    /**
     * Get channel states for a turret user
     */
    getTurretChannelStates(turretUserId: number): Observable<ChannelState[]> {
        return this.http.get<{ data: ChannelState[] }>(`${this.API_URL}/turret-channel-states?turret_user_id=${turretUserId}`, { headers: this.getAuthHeaders() }).pipe(
            map(response => response.data || []),
            catchError(err => {
                console.error('[CMS] Failed to fetch channel states:', err);
                return of([]);
            })
        );
    }

    /**
     * Save or update a channel state
     */
    saveTurretChannelState(state: ChannelState): Observable<ChannelState | null> {
        if (state.id) {
            // Update existing
            return this.http.put<{ data: ChannelState }>(`${this.API_URL}/turret-channel-states/${state.id}`, state, { headers: this.getAuthHeaders() }).pipe(
                map(response => response.data),
                catchError(err => {
                    console.error('[CMS] Failed to update channel state:', err);
                    return of(null);
                })
            );
        } else {
            // Create new
            return this.http.post<{ data: ChannelState }>(`${this.API_URL}/turret-channel-states`, state, { headers: this.getAuthHeaders() }).pipe(
                map(response => response.data),
                catchError(err => {
                    console.error('[CMS] Failed to save channel state:', err);
                    return of(null);
                })
            );
        }
    }

    /**
     * Delete a channel state
     */
    deleteTurretChannelState(id: number): Observable<boolean> {
        return this.http.delete<any>(`${this.API_URL}/turret-channel-states/${id}`, { headers: this.getAuthHeaders() }).pipe(
            map(() => true),
            catchError(err => {
                console.error('[CMS] Failed to delete channel state:', err);
                return of(false);
            })
        );
    }

    // ==================== EXTENSIONS LIST ====================

    /**
     * Get all extensions as simple list for Turret drawer
     */
    getExtensionsList(): Observable<{ number: string; online: boolean }[]> {
        return this.http.get<{ data: any[] }>(`${this.API_URL}/extensions`, { headers: this.getAuthHeaders() }).pipe(
            map(response => (response.data || []).map(ext => ({
                number: ext.extension_number || ext.extension || String(ext.id),
                online: ext.is_active !== false
            }))),
            catchError(err => {
                console.error('[CMS] Failed to fetch extensions list:', err);
                return of([]);
            })
        );
    }

    // ==================== SYSTEM CONFIG ====================

    /**
     * Get system configuration (SIP server, etc.)
     */
    getSystemConfig(): Observable<SystemConfig> {
        return this.http.get<{ data: any[] }>(`${this.API_URL}/system-config`, { headers: this.getAuthHeaders() }).pipe(
            map(response => {
                const config: SystemConfig = {
                    sip_server: '103.154.80.172',
                    sip_port: 5060,
                    stun_server: 'stun:stun.l.google.com:19302'
                };
                // Parse config from array of key-value pairs
                (response.data || []).forEach(item => {
                    if (item.config_key === 'sip_server') config.sip_server = item.config_value;
                    if (item.config_key === 'sip_port') config.sip_port = parseInt(item.config_value) || 5060;
                    if (item.config_key === 'stun_server') config.stun_server = item.config_value;
                });
                return config;
            }),
            catchError(err => {
                console.warn('[CMS] Failed to fetch system config, using defaults:', err);
                return of({
                    sip_server: '103.154.80.172',
                    sip_port: 5060,
                    stun_server: 'stun:stun.l.google.com:19302'
                });
            })
        );
    }
}

// ==================== INTERFACES ====================

export interface ChannelState {
    id?: number;
    turret_user_id: number;
    channel_key: string;
    contact_name: string;
    extension: string;
    volume_in: number;
    volume_out: number;
    is_ptt: boolean;
    group_ids: string[];
}

export interface SystemConfig {
    sip_server: string;
    sip_port: number;
    stun_server: string;
}
