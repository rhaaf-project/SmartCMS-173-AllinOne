// SipService - JsSIP integration for SIP/WSS communication
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import * as JsSIP from 'jssip';
import { AudioService } from './audio.service';

export interface SipConfig {
    server: string;
    port: number;
    extension: string;
    password: string;
}

export interface SipSession {
    channelKey: string;
    session: any; // JsSIP.RTCSession - using any due to incomplete type exports
    direction: 'incoming' | 'outgoing';
    state: 'connecting' | 'connected' | 'ended';
}

@Injectable({
    providedIn: 'root'
})
export class SipService {
    private ua: JsSIP.UA | null = null;
    private activeSessions = new BehaviorSubject<Map<string, SipSession>>(new Map());
    private registrationStatus = new BehaviorSubject<'unregistered' | 'registering' | 'registered' | 'failed'>('unregistered');
    private lineBusyStatus = new BehaviorSubject<Map<string, boolean>>(new Map());
    private incomingCall = new BehaviorSubject<{ number: string, channelKey: string } | null>(null);
    private sessionEnded = new BehaviorSubject<string | null>(null);

    // Store remote audio elements to prevent garbage collection
    private remoteAudioElements = new Map<string, HTMLAudioElement>();

    public activeSessions$ = this.activeSessions.asObservable();
    public registrationStatus$ = this.registrationStatus.asObservable();
    public lineBusyStatus$ = this.lineBusyStatus.asObservable();
    public incomingCall$ = this.incomingCall.asObservable();
    public sessionEnded$ = this.sessionEnded.asObservable();

    constructor(private audioService: AudioService) {
        // Enable JsSIP debug in development
        JsSIP.debug.enable('JsSIP:*');

        // Subscribe to output device changes to update active calls
        this.audioService.selectedOutputDeviceId$.subscribe(deviceId => {
            this.applyOutputDeviceToAllCalls(deviceId);
        });
    }

    /**
     * Apply output device to all active audio elements
     */
    private applyOutputDeviceToAllCalls(deviceId: string): void {
        const remoteAudio = document.getElementById('remoteAudio') as HTMLAudioElement;
        if (remoteAudio && (remoteAudio as any).setSinkId) {
            (remoteAudio as any).setSinkId(deviceId)
                .then(() => console.log('[SIP] Applied output device:', deviceId))
                .catch((err: any) => console.warn('[SIP] setSinkId error:', err));
        }
    }

    /**
     * Register extension to PBX via WebSocket
     */
    registerExtension(config: SipConfig): void {
        const wsUri = `ws://${config.server}:${config.port}/ws`;
        const sipUri = `sip:${config.extension}@${config.server}`;

        const socket = new JsSIP.WebSocketInterface(wsUri);

        const uaConfig = {
            sockets: [socket],
            uri: sipUri,
            password: config.password,
            register: true
            // Removed session_timers: false - match SmartX default
        };


        this.ua = new JsSIP.UA(uaConfig);

        this.ua.on('registered', () => {
            console.log(`[SIP] Registered: ${config.extension}`);
            this.registrationStatus.next('registered');
        });

        this.ua.on('unregistered', () => {
            console.log(`[SIP] Unregistered: ${config.extension}`);
            this.registrationStatus.next('unregistered');
        });

        this.ua.on('registrationFailed', (e: any) => {
            console.error(`[SIP] Registration failed: ${e.cause}`);
            this.registrationStatus.next('failed');
        });

        // Handle WebSocket disconnect - auto reconnect
        this.ua.on('disconnected', () => {
            console.warn('[SIP] ⚠️ WebSocket disconnected - will try to reconnect');
            this.registrationStatus.next('unregistered');

            // Auto-reconnect after 3 seconds
            setTimeout(() => {
                if (this.ua && this.registrationStatus.getValue() !== 'registered') {
                    console.log('[SIP] 🔄 Attempting auto-reconnect...');
                    this.ua.start();
                }
            }, 3000);
        });

        // Handle connection errors
        this.ua.on('connecting', () => {
            console.log('[SIP] 🔌 Connecting to WebSocket...');
        });

        this.ua.on('connected', () => {
            console.log('[SIP] ✅ WebSocket connected');
        });

        this.ua.on('newRTCSession', (data: any) => {
            this.handleNewSession(data);
        });

        this.registrationStatus.next('registering');
        this.ua.start();
    }

    /**
     * Make outgoing call - SmartX Pattern
     */
    makeCall(targetUri: string, channelKey: string): void {
        if (!this.ua) {
            console.error('[SIP] UA not initialized');
            return;
        }

        console.log(`[SIP] Making call to ${targetUri} for channel ${channelKey}`);

        // Get selected microphone
        const inputDeviceId = this.audioService.getSelectedInputDeviceId();
        const audioConstraints = inputDeviceId && inputDeviceId !== 'default'
            ? { deviceId: { exact: inputDeviceId } }
            : true;

        // Get microphone stream FIRST (like SmartX)
        navigator.mediaDevices.getUserMedia({ audio: audioConstraints }).then((stream) => {
            // Mute mic by default (PTT mode) - same as incoming calls
            if (stream.getAudioTracks().length > 0) {
                stream.getAudioTracks()[0].enabled = false;
                console.log('[SIP] 🔇 Outgoing call: Mic auto-muted (PTT mode)');
            }

            // Empty iceServers - let Asterisk handle media with rtp_symmetric
            const session = this.ua!.call(targetUri, {
                mediaStream: stream,
                pcConfig: { iceServers: [] }
            });

            // Use session.connection.addEventListener like SmartX
            session.connection.addEventListener('track', (e: RTCTrackEvent) => {
                console.log('[SIP] Remote track received for:', channelKey);
                const remoteAudio = document.getElementById('remoteAudio') as HTMLAudioElement;
                if (remoteAudio) {
                    remoteAudio.srcObject = e.streams[0];
                    remoteAudio.play().catch(err => console.error('[SIP] Audio play error:', err));

                    // Apply selected speaker (always apply, even for 'default')
                    const outputDeviceId = this.audioService.getSelectedOutputDeviceId();
                    if ((remoteAudio as any).setSinkId) {
                        (remoteAudio as any).setSinkId(outputDeviceId)
                            .then(() => console.log('[SIP] Audio output set to:', outputDeviceId))
                            .catch((err: any) => console.warn('[SIP] setSinkId error:', err));
                    }
                }
            });

            session.on('confirmed', () => {
                console.log(`[SIP] ✅ Call connected: ${channelKey}`);
            });

            session.on('progress', () => {
                console.log(`[SIP] Progress (ringing): ${channelKey}`);
            });

            session.on('failed', (e: any) => {
                console.error(`[SIP] Call failed for ${channelKey}:`, e?.cause || 'Unknown reason');
            });

            session.on('ended', () => {
                console.log(`[SIP] Call ended for ${channelKey}`);
            });

            this.addSession(channelKey, session, 'outgoing');

        }).catch((err) => {
            console.error('[SIP] Mic access error:', err);
        });
    }

    /**
     * Answer incoming call - SmartX Pattern
     */
    answerCall(channelKey: string): void {
        const sessions = this.activeSessions.getValue();
        const sipSession = sessions.get(channelKey);

        if (sipSession && sipSession.direction === 'incoming') {
            const session = sipSession.session;

            // Get selected microphone
            const inputDeviceId = this.audioService.getSelectedInputDeviceId();
            const audioConstraints = inputDeviceId && inputDeviceId !== 'default'
                ? { deviceId: { exact: inputDeviceId } }
                : true;

            // SmartX pattern: getUserMedia FIRST, then answer
            navigator.mediaDevices.getUserMedia({ audio: audioConstraints }).then((stream) => {
                // Mute mic by default (PTT mode) - like SmartX
                if (stream.getAudioTracks().length > 0) {
                    stream.getAudioTracks()[0].enabled = false;
                    console.log('[SIP] 🔇 Mic auto-muted (PTT mode)');
                }

                // Empty iceServers - let Asterisk handle media
                session.answer({
                    mediaStream: stream,
                    pcConfig: { iceServers: [] }
                });

                // Setup audio output using session.connection (like SmartX)
                session.connection.addEventListener('track', (e: RTCTrackEvent) => {
                    console.log('[SIP] Remote track received for incoming:', channelKey);
                    const remoteAudio = document.getElementById('remoteAudio') as HTMLAudioElement;
                    if (remoteAudio) {
                        remoteAudio.srcObject = e.streams[0];
                        remoteAudio.play().catch(err => console.error('[SIP] Audio play error:', err));

                        // SmartX: Do NOT mute remote audio - user can always HEAR
                        // PTT only controls MIC (speaking), not hearing

                        // Apply selected speaker (always apply, even for 'default')
                        const outputDeviceId = this.audioService.getSelectedOutputDeviceId();
                        if ((remoteAudio as any).setSinkId) {
                            (remoteAudio as any).setSinkId(outputDeviceId)
                                .then(() => console.log('[SIP] Audio output set to:', outputDeviceId))
                                .catch((err: any) => console.warn('[SIP] setSinkId error:', err));
                        }
                    }
                });

                session.on('confirmed', () => {
                    console.log('[SIP] ✅ Incoming call connected:', channelKey);
                });

            }).catch((err) => {
                console.error('[SIP] Mic access error for incoming:', err);
                session.terminate();
            });
        }
    }

    /**
     * Hangup call
     */
    hangupCall(channelKey: string): void {
        const sessions = this.activeSessions.getValue();
        const sipSession = sessions.get(channelKey);

        if (sipSession) {
            sipSession.session.terminate();
            this.removeSession(channelKey);

            // Cleanup audio element
            const audioEl = this.remoteAudioElements.get(channelKey);
            if (audioEl) {
                audioEl.pause();
                audioEl.srcObject = null;
                this.remoteAudioElements.delete(channelKey);
                console.log('[SIP] Audio element cleaned up for:', channelKey);
            }
        }
    }

    /**
     * Send DTMF tone
     */
    sendDTMF(channelKey: string, tone: string): void {
        const sessions = this.activeSessions.getValue();
        const sipSession = sessions.get(channelKey);

        if (sipSession) {
            sipSession.session.sendDTMF(tone);
        }
    }

    /**
     * Get audio stream from session for visualizer
     */
    getRemoteAudioStream(channelKey: string): MediaStream | null {
        const sessions = this.activeSessions.getValue();
        const sipSession = sessions.get(channelKey);

        if (sipSession) {
            const connection = sipSession.session.connection;
            if (connection) {
                const receivers = connection.getReceivers();
                const audioReceiver = receivers.find((r: RTCRtpReceiver) => r.track.kind === 'audio');
                if (audioReceiver) {
                    return new MediaStream([audioReceiver.track]);
                }
            }
        }
        return null;
    }

    /**
     * Mute local audio (mic) for PTT mode
     */
    muteChannel(channelKey: string): void {
        const sessions = this.activeSessions.getValue();
        const sipSession = sessions.get(channelKey);

        if (sipSession && sipSession.session.connection) {
            const senders = sipSession.session.connection.getSenders();
            senders.forEach((sender: RTCRtpSender) => {
                if (sender.track && sender.track.kind === 'audio') {
                    sender.track.enabled = false;
                    console.log('[SIP] 🔇 Mic muted for:', channelKey);
                }
            });
        }
    }

    /**
     * Unmute local audio (mic) for PTT mode  
     */
    unmuteChannel(channelKey: string): void {
        const sessions = this.activeSessions.getValue();
        const sipSession = sessions.get(channelKey);

        if (sipSession && sipSession.session.connection) {
            const senders = sipSession.session.connection.getSenders();
            senders.forEach((sender: RTCRtpSender) => {
                if (sender.track && sender.track.kind === 'audio') {
                    sender.track.enabled = true;
                    console.log('[SIP] 🎤 Mic unmuted for:', channelKey);
                }
            });
        }
    }

    /**
     * Disconnect and cleanup
     */
    disconnect(): void {
        if (this.ua) {
            this.ua.stop();
            this.ua = null;
        }
        this.activeSessions.next(new Map());
        this.registrationStatus.next('unregistered');
    }

    /**
     * Unregister from PBX (alias for disconnect)
     */
    unregister(): void {
        this.disconnect();
    }

    private handleNewSession(data: any): void {
        const { originator, session, request } = data;
        const direction: 'incoming' | 'outgoing' = originator === 'remote' ? 'incoming' : 'outgoing';

        // For incoming calls, get caller number from request
        const channelKey = `incoming-${Date.now()}`;

        if (direction === 'incoming') {
            const callerNumber = request?.from?.uri?.user || 'Unknown';
            console.log(`[SIP] Incoming call from: ${callerNumber}`);

            // Emit incoming call for UI notification
            this.incomingCall.next({ number: callerNumber, channelKey });

            // Auto-play ringtone (could be enhanced)
            session.on('ended', () => {
                this.incomingCall.next(null);
            });
            session.on('failed', () => {
                this.incomingCall.next(null);
            });
        }

        this.addSession(channelKey, session, direction);
    }

    private addSession(channelKey: string, session: any, direction: 'incoming' | 'outgoing'): void {
        const sipSession: SipSession = {
            channelKey,
            session,
            direction,
            state: 'connecting'
        };

        session.on('confirmed', () => {
            sipSession.state = 'connected';
            this.updateSession(channelKey, sipSession);
        });

        session.on('ended', () => {
            console.log(`[SIP] Session ended: ${channelKey}`);
            this.sessionEnded.next(channelKey);
            this.removeSession(channelKey);
        });

        session.on('failed', (e: any) => {
            console.log(`[SIP] Session failed: ${channelKey}`, e?.cause || '');
            this.removeSession(channelKey);
        });

        const sessions = new Map(this.activeSessions.getValue());
        sessions.set(channelKey, sipSession);
        this.activeSessions.next(sessions);
    }

    private updateSession(channelKey: string, sipSession: SipSession): void {
        const sessions = new Map(this.activeSessions.getValue());
        sessions.set(channelKey, sipSession);
        this.activeSessions.next(sessions);
    }

    private removeSession(channelKey: string): void {
        const sessions = new Map(this.activeSessions.getValue());
        sessions.delete(channelKey);
        this.activeSessions.next(sessions);
    }
}
